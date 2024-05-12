import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from rotkehlchen.chain.ethereum.utils import token_normalized_value_decimals
from rotkehlchen.chain.evm.constants import ZERO_ADDRESS
from rotkehlchen.chain.evm.decoding.constants import ERC20_OR_ERC721_TRANSFER
from rotkehlchen.chain.evm.decoding.interfaces import DecoderInterface
from rotkehlchen.chain.evm.decoding.structures import (
    DEFAULT_DECODING_OUTPUT,
    ActionItem,
    DecoderContext,
    DecodingOutput,
)
from rotkehlchen.chain.evm.decoding.types import CounterpartyDetails
from rotkehlchen.chain.evm.decoding.utils import maybe_reshuffle_events
from rotkehlchen.constants.assets import A_ETH, A_STETH, A_WSTETH
from rotkehlchen.fval import FVal
from rotkehlchen.history.events.structures.types import HistoryEventSubType, HistoryEventType
from rotkehlchen.logging import RotkehlchenLogsAdapter
from rotkehlchen.types import ChecksumEvmAddress, EvmTransaction
from rotkehlchen.utils.misc import hex_or_bytes_to_address, hex_or_bytes_to_int

from .constants import (
    CPT_LIDO_ETH,
    LIDO_STETH_SUBMITTED,
    LIDO_STETH_TRANSFER_SHARES,
    STETH_MAX_ROUND_ERROR_WEI,
)

if TYPE_CHECKING:
    from rotkehlchen.chain.evm.decoding.base import BaseDecoderTools
    from rotkehlchen.chain.evm.node_inquirer import EvmNodeInquirer
    from rotkehlchen.chain.evm.structures import EvmTxReceiptLog
    from rotkehlchen.history.events.structures.evm_event import EvmEvent
    from rotkehlchen.user_messages import MessagesAggregator

logger = logging.getLogger(__name__)
log = RotkehlchenLogsAdapter(logger)


class LidoDecoder(DecoderInterface):

    def __init__(
            self,
            evm_inquirer: 'EvmNodeInquirer',
            base_tools: 'BaseDecoderTools',
            msg_aggregator: 'MessagesAggregator',
    ) -> None:
        super().__init__(
            evm_inquirer=evm_inquirer,
            base_tools=base_tools,
            msg_aggregator=msg_aggregator,
        )
        self.steth_evm_address = A_STETH.resolve_to_evm_token().evm_address
        self.wsteth_evm_address = A_WSTETH.resolve_to_evm_token().evm_address

    def _decode_lido_staking_in_steth(self, context: DecoderContext) -> DecodingOutput:
        """Decode the submit of eth to lido contract for obtaining steth in return"""
        sender_address = hex_or_bytes_to_address(context.tx_log.topics[1])
        amount_raw = hex_or_bytes_to_int(context.tx_log.data[:32])
        collateral_amount = token_normalized_value_decimals(
            token_amount=amount_raw,
            token_decimals=18,
        )

        # Searching for the exact paired stETH token reception for validating the decoding
        steth_minted_tokens = None
        # Here searching for the paired stETH mint operation, with a hacky way for the issue:
        # https://github.com/lidofinance/lido-dao/issues/442
        for tx_log in context.all_logs:
            if (
                tx_log.address == self.steth_evm_address and
                tx_log.topics[0] == ERC20_OR_ERC721_TRANSFER and
                hex_or_bytes_to_address(tx_log.topics[1]) == ZERO_ADDRESS and  # from
                hex_or_bytes_to_address(tx_log.topics[2]) == sender_address and  # to
                abs(amount_raw - hex_or_bytes_to_int(tx_log.data[:32])) < STETH_MAX_ROUND_ERROR_WEI
            ):
                steth_minted_tokens = token_normalized_value_decimals(
                    token_amount=hex_or_bytes_to_int(tx_log.data[:32]),
                    token_decimals=18,
                )
                break
        else:  # did not break/find anything
            log.error(
                f'At lido steth submit decoding of tx {context.transaction.tx_hash.hex()}'
                f'did not find the related stETH token generation',
            )
            return DEFAULT_DECODING_OUTPUT

        # Searching for the already decoded event,
        # containing the ETH transfer of the submit transaction
        paired_event = None
        for event in context.decoded_events:
            if (
                event.address == self.steth_evm_address and
                event.asset == A_ETH and
                event.balance.amount == collateral_amount and
                event.event_type == HistoryEventType.SPEND and
                event.location_label == sender_address
            ):
                event.event_type = HistoryEventType.DEPOSIT
                event.event_subtype = HistoryEventSubType.DEPOSIT_ASSET
                event.notes = f'Submit {collateral_amount} ETH to Lido for receiving stETH in exchange'  # noqa: E501
                event.counterparty = CPT_LIDO_ETH
                #  preparing next action to be processed when erc20 transfer will be decoded by rotki  # noqa: E501
                #  needed because submit levent is emitted prior of erc20 transfer, so it is not decoded yet  # noqa: E501
                # TODO: to be confirmed with ROTKI team if it is not possible to have the erc20 event available before this decoder is called  # noqa: E501
                paired_event = event
                action_from_event_type = HistoryEventType.RECEIVE
                action_to_event_subtype = HistoryEventSubType.RECEIVE_WRAPPED
                action_to_notes = f'Receive {{amount}} stETH in exchange of the deposited ETH'  # {amount} to be replaced in post decoding  # noqa: F541,E501
                break

        action_items = []  # also create an action item for the reception of the stETH tokens
        if paired_event is not None and action_from_event_type is not None:
            action_items.append(ActionItem(
                action='transform',
                from_event_type=action_from_event_type,
                from_event_subtype=HistoryEventSubType.NONE,
                asset=A_STETH,
                amount=steth_minted_tokens,
                to_event_subtype=action_to_event_subtype,
                to_notes=action_to_notes,
                to_counterparty=CPT_LIDO_ETH,
                paired_event_data=(paired_event, True),
                extra_data={'staked_eth': str(collateral_amount)},
            ))
        else:  # did not break/find anything
            log.error(
                f'At lido steth submit decoding of tx {context.transaction.tx_hash.hex()}'
                f'did not find the decoded event of the ETH transfer',
            )
            return DEFAULT_DECODING_OUTPUT

        return DecodingOutput(action_items=action_items, matched_counterparty=CPT_LIDO_ETH)

    def _map_erc20_lido_token_transfer(
            self,
            decoded_events: list['EvmEvent'],
            transaction: 'EvmTransaction',  # pylint: disable=unused-argument
            all_logs: list['EvmTxReceiptLog'],  # pylint: disable=unused-argument
    ) -> list['EvmEvent']:
        """Post decoding function to map the ERC20 Lido tokens reception"""
        """TODO: To be checked with Rotki team, I am adding post decoding because I see that ERC20
        transfers are not available in decoded_events at the time of decode by address rules
        from what I have seen in the code. I got this solution looking at compound rules"""
        for event in decoded_events:
            if (
                (event.counterparty == CPT_LIDO_ETH and event.notes is not None and event.extra_data is not None) and  # noqa: E501
                (
                    (event.event_type == HistoryEventType.RECEIVE and event.event_subtype == HistoryEventSubType.RECEIVE_WRAPPED) or  # noqa: E501
                    (event.event_type == HistoryEventType.SPEND and event.event_subtype == HistoryEventSubType.RETURN_WRAPPED)  # noqa: E501
                )
            ):
                event.notes = event.notes.format(amount=event.balance.amount)  # set the amount  # noqa: E501
                break
        return decoded_events

    def _decode_lido_transfer_shares_for_steth_wrap(
            self, context: DecoderContext,
    ) -> DecodingOutput:
        """Decode steth wrapping in wsteth from TransferShares log event"""
        user_address = hex_or_bytes_to_address(context.tx_log.topics[1])

        #  we need to retrieve the transferred stETH amount deterministically.
        #  expected log index for the transferred steth is -1
        #  expected log index for the transferred wsteth is -3
        expected_steth_transfer_index = context.tx_log.log_index - 1
        expected_wsteth_transfer_index = context.tx_log.log_index - 3
        paired_wsteth_ratio = None
        sth_wrapped_amount = None
        wsteth_received_amount = None

        for tx_log in context.all_logs:
            if (
                tx_log.log_index == expected_steth_transfer_index and
                tx_log.topics[0] == ERC20_OR_ERC721_TRANSFER and
                tx_log.address == self.steth_evm_address and
                hex_or_bytes_to_address(tx_log.topics[1]) == user_address and  # from
                hex_or_bytes_to_address(tx_log.topics[2]) == self.wsteth_evm_address  # to # wsteth
            ):
                sth_wrapped_amount = token_normalized_value_decimals(
                    token_amount=hex_or_bytes_to_int(tx_log.data[:32]),
                    token_decimals=18,
                )
            elif (
                tx_log.log_index == expected_wsteth_transfer_index and
                tx_log.topics[0] == ERC20_OR_ERC721_TRANSFER and
                tx_log.address == self.wsteth_evm_address and
                hex_or_bytes_to_address(tx_log.topics[1]) == ZERO_ADDRESS and  # from
                hex_or_bytes_to_address(tx_log.topics[2]) == user_address  # to # wsteth
            ):
                wsteth_received_amount = token_normalized_value_decimals(
                    token_amount=hex_or_bytes_to_int(tx_log.data[:32]),
                    token_decimals=18,
                )

            if sth_wrapped_amount and wsteth_received_amount:
                paired_wsteth_ratio = FVal(sth_wrapped_amount) / FVal(wsteth_received_amount)
                break

        if paired_wsteth_ratio is None:
            return DEFAULT_DECODING_OUTPUT

        in_event = None
        out_event = None
        for event in context.decoded_events:
            if (
                event.event_type == HistoryEventType.SPEND and
                event.event_subtype == HistoryEventSubType.NONE and
                event.asset == A_STETH and
                event.balance.amount == sth_wrapped_amount and
                event.address == self.wsteth_evm_address
            ):
                event.event_type = HistoryEventType.DEPOSIT
                event.event_subtype = HistoryEventSubType.DEPOSIT_ASSET
                event.counterparty = CPT_LIDO_ETH
                event.notes = f'Send {sth_wrapped_amount} stETH for wrapping at wstETH ratio {paired_wsteth_ratio}'  # noqa: E501
                out_event = event
            elif (
                event.event_type == HistoryEventType.RECEIVE and
                event.event_subtype == HistoryEventSubType.NONE and
                event.asset == A_WSTETH and
                event.balance.amount == wsteth_received_amount and
                event.address == ZERO_ADDRESS
            ):
                event.event_type = HistoryEventType.RECEIVE
                event.event_subtype = HistoryEventSubType.RECEIVE_WRAPPED
                event.counterparty = CPT_LIDO_ETH
                event.notes = f'Receive {wsteth_received_amount} wstETH in exchange of the deposited stETH at wstETH ratio {paired_wsteth_ratio}'  # {amount} to be replaced in post decoding  # noqa: E501,
                in_event = event
        if in_event and out_event:
            maybe_reshuffle_events(
                ordered_events=[out_event, in_event],
                events_list=context.decoded_events,
            )

        return DecodingOutput(matched_counterparty=CPT_LIDO_ETH, refresh_balances=True)

    def _decode_lido_transfer_shares_for_wsteth_unwrap(
            self, context: DecoderContext,
    ) -> DecodingOutput:
        """Decode wsteth unwrapping in steth from TransferShares log event"""
        user_address = hex_or_bytes_to_address(context.tx_log.topics[2])

        paired_wsteth_ratio = None
        # we need to retrieve the transferred amount deterministically.
        # log index baseline: transferShares log index
        # expect log index for the transferred steth is -1
        # expect log index for the transferred steth is -2
        expected_steth_transfer_index = context.tx_log.log_index - 1
        expected_wsteth_transfer_index = context.tx_log.log_index - 2
        sth_received_amount = None
        wsteth_unwrapped_amount = None
        for tx_log in context.all_logs:
            if (
                tx_log.log_index == expected_steth_transfer_index and
                tx_log.topics[0] == ERC20_OR_ERC721_TRANSFER and
                tx_log.address == self.steth_evm_address and
                hex_or_bytes_to_address(tx_log.topics[1]) == self.wsteth_evm_address and  # from
                hex_or_bytes_to_address(tx_log.topics[2]) == user_address  # to # wsteth
            ):
                sth_received_amount = token_normalized_value_decimals(
                    token_amount=hex_or_bytes_to_int(tx_log.data[:32]),
                    token_decimals=18,
                )
            elif (
                tx_log.log_index == expected_wsteth_transfer_index and
                tx_log.topics[0] == ERC20_OR_ERC721_TRANSFER and
                tx_log.address == self.wsteth_evm_address and
                hex_or_bytes_to_address(tx_log.topics[1]) == user_address and  # from
                hex_or_bytes_to_address(tx_log.topics[2]) == ZERO_ADDRESS  # to # wsteth
            ):
                wsteth_unwrapped_amount = token_normalized_value_decimals(
                    token_amount=hex_or_bytes_to_int(tx_log.data[:32]),
                    token_decimals=18,
                )

            if sth_received_amount and wsteth_unwrapped_amount:
                paired_wsteth_ratio = FVal(sth_received_amount) / FVal(wsteth_unwrapped_amount)
                break

        if paired_wsteth_ratio is None:
            return DEFAULT_DECODING_OUTPUT
        in_event = None
        out_event = None
        for event in context.decoded_events:
            if (
                event.event_type == HistoryEventType.SPEND and
                event.event_subtype == HistoryEventSubType.NONE and
                event.asset == A_WSTETH and
                event.balance.amount == wsteth_unwrapped_amount and
                event.address == ZERO_ADDRESS
            ):
                event.event_subtype = HistoryEventSubType.RETURN_WRAPPED
                event.counterparty = CPT_LIDO_ETH
                event.notes = f'Send {wsteth_unwrapped_amount} wstETH for unwrapping at wstETH ratio {paired_wsteth_ratio}'  # noqa: E501
                out_event = event
            elif (
                event.event_type == HistoryEventType.RECEIVE and
                event.event_subtype == HistoryEventSubType.NONE and
                event.asset == A_STETH and
                event.balance.amount == sth_received_amount and
                event.address == self.wsteth_evm_address
            ):
                event.event_type = HistoryEventType.WITHDRAWAL  # TODO: decide the right mappings
                event.event_subtype = HistoryEventSubType.REMOVE_ASSET
                event.counterparty = CPT_LIDO_ETH
                event.notes = f'Receive {sth_received_amount} stETH in exchange of the returned wstETH at wstETH ratio {paired_wsteth_ratio}'  # noqa: E501
                in_event = event

            if in_event and out_event:
                break

        if in_event and out_event:
            maybe_reshuffle_events(
                ordered_events=[out_event, in_event],
                events_list=context.decoded_events,
            )

        return DecodingOutput(matched_counterparty=CPT_LIDO_ETH, refresh_balances=True)

    def _decode_steth_wrap_unwrap(
            self, context: DecoderContext,
    ) -> DecodingOutput:
        """Decode stETH wrap or unwrap"""

        # in this case, the post-decoding is not needed because the TransferShare event is the last one  # noqa: E501

        # decoding the TransferShares because there is no wrap/unwrap event log
        # Here we detemernistically check the near log indexes to determine if
        # it is a wrapping or unwrapping operation
        transfer_shares_from_address = hex_or_bytes_to_address(context.tx_log.topics[1])
        transfer_shares_to_address = hex_or_bytes_to_address(context.tx_log.topics[2])

        if (  # check
            self.base.is_tracked(transfer_shares_from_address) and
            transfer_shares_to_address == self.wsteth_evm_address
        ):
            # this is a wrap operation
            return self._decode_lido_transfer_shares_for_steth_wrap(
                context=context,
            )
        elif (
            transfer_shares_from_address == self.wsteth_evm_address and
            self.base.is_tracked(transfer_shares_to_address)
        ):
            # this is an uwrap operation
            return self._decode_lido_transfer_shares_for_wsteth_unwrap(
                context=context,
            )

        return DEFAULT_DECODING_OUTPUT

    def _maybe_decode_lido_staking_with_eth_transfer_to_wsteth(
            self, context: DecoderContext,
    ) -> DecodingOutput:
        """Decode sumbit from wstETH contract for detecting the staking done with
           direct transfer of ETH to wstETH contract, for obtaiting wstETH in return"""

        #  Retrieve from submit event log the ETH amount transfered by wsteth contract to steh
        sender_address = hex_or_bytes_to_address(context.tx_log.topics[1])
        referral_address = hex_or_bytes_to_address(context.tx_log.data[32:])
        amount_raw = hex_or_bytes_to_int(context.tx_log.data[:32])

        if (  # ensure that submit is coming from wseth contract
            referral_address != ZERO_ADDRESS or  # zero address in this case of submit trough wsteth contract  # noqa: E501
            sender_address != self.wsteth_evm_address
        ):
            return DEFAULT_DECODING_OUTPUT

        # save the amount of deposited amount for finding the related decoded event
        eth_deposited_amount = token_normalized_value_decimals(
            token_amount=amount_raw,
            token_decimals=18,
        )

        """
        from here, we need to search deterministically for log events related to this submit call,
        because the sender address of submit call is wstETH contract, so we can map the event if,
        and only if, there is related amount of wstETH tokens sent to the tracked address
        """
        wsteth_minted_tokens = None
        steth_minted_tokens = None
        # Here searching for the paired stETH mint operation in the same transaction,
        # with an hacky way for the issue: https://github.com/lidofinance/lido-dao/issues/442
        # Also searching for the paired transferShares to know the amount of wsteth expected to be received.  # noqa: E501
        # Steth mint operation is searched only for logging which was the wsteth/steth pair at the moment of the transaction  # noqa: E501

        # Using submit event tx_log index as baseline:
        # At submit tx_log index + 1 is expected to have the ERC20 transfer from stETH to wstETH contract  # noqa: E501
        # we collect the stETH amount for calculating the wstETH ratio at the time of the transaction  # noqa: E501
        # At submit tx_log index + 3 is expected to have the ERC20 transfer,  from wstETH contract to the user  # noqa: E501
        submit_tx_log_index = context.tx_log.log_index
        steth_transfer_tx_log_index = submit_tx_log_index + 1
        wsteth_transfer_tx_log_index = submit_tx_log_index + 3
        for tx_log in context.all_logs:
            if (
                tx_log.log_index == steth_transfer_tx_log_index and
                tx_log.topics[0] == ERC20_OR_ERC721_TRANSFER and
                tx_log.address == self.steth_evm_address and
                hex_or_bytes_to_address(tx_log.topics[1]) == ZERO_ADDRESS and  # from
                hex_or_bytes_to_address(tx_log.topics[2]) == self.wsteth_evm_address and  # to # wsteth is submitting on behalf of user  # noqa: E501
                abs(amount_raw - hex_or_bytes_to_int(tx_log.data[:32])) < STETH_MAX_ROUND_ERROR_WEI
            ):
                steth_minted_tokens = token_normalized_value_decimals(
                    token_amount=hex_or_bytes_to_int(tx_log.data[:32]),
                    token_decimals=18,
                )
            elif (
                tx_log.log_index == wsteth_transfer_tx_log_index and  # wsteth transfer event to the user address  # noqa: E501
                tx_log.topics[0] == ERC20_OR_ERC721_TRANSFER and
                tx_log.address == self.wsteth_evm_address and
                hex_or_bytes_to_address(tx_log.topics[1]) == ZERO_ADDRESS and  # from
                self.base.is_tracked(hex_or_bytes_to_address(tx_log.topics[2]))  # to user address  # noqa: E501
            ):
                wsteth_minted_tokens = token_normalized_value_decimals(
                    token_amount=hex_or_bytes_to_int(tx_log.data[:32]),
                    token_decimals=18,
                )

            if steth_minted_tokens and wsteth_minted_tokens:
                break

        if not steth_minted_tokens or not wsteth_minted_tokens:  # did not find the related events
            log.error(
                f'At lido wsteth submit decoding of tx {context.transaction.tx_hash.hex()}'
                f'did not find any stETH/wstETH token generation',
            )
            return DEFAULT_DECODING_OUTPUT

        #  Store the calculated wstETH ratio at the moment of the transaction for later uses
        paired_wsteth_ratio = FVal(steth_minted_tokens) / FVal(wsteth_minted_tokens)
        paired_eth_transfer_event = None
        #  Search for the related already decoded ETH transfer,
        #  pairing with the submit performed by wstETH on behalf of user
        for event in context.decoded_events:
            if (
                event.address == self.wsteth_evm_address and
                event.balance.amount == eth_deposited_amount and
                event.event_type == HistoryEventType.SPEND and
                event.asset == A_ETH
            ):
                event.event_type = HistoryEventType.DEPOSIT
                event.event_subtype = HistoryEventSubType.DEPOSIT_ASSET
                event.notes = f'Submit {eth_deposited_amount} ETH to Lido for receiving wstETH in exchange at wstETH ratio {paired_wsteth_ratio}'  # noqa: E501
                event.counterparty = CPT_LIDO_ETH
                # preparing next action to be processed when erc20 transfer is called by rotki
                paired_eth_transfer_event = event
                action_from_event_type = HistoryEventType.RECEIVE
                action_to_event_subtype = HistoryEventSubType.RECEIVE_WRAPPED
                action_to_notes = f'Receive {{amount}} wstETH in exchange of the deposited ETH at wstETH ratio {paired_wsteth_ratio}'  # {amount} to be replaced in post decoding  # noqa: E501

        action_items = []  # also create an action item for the receive of the wstETH tokens
        if paired_eth_transfer_event is not None and action_from_event_type is not None:
            action_items.append(ActionItem(
                action='transform',
                from_event_type=action_from_event_type,
                from_event_subtype=HistoryEventSubType.NONE,
                asset=A_WSTETH,
                amount=wsteth_minted_tokens,
                to_event_subtype=action_to_event_subtype,
                to_notes=action_to_notes,
                to_counterparty=CPT_LIDO_ETH,
                paired_event_data=(paired_eth_transfer_event, True),
                extra_data={'staked_eth': str(eth_deposited_amount)},
            ))

        return DecodingOutput(action_items=action_items, matched_counterparty=CPT_LIDO_ETH)

    def _decode_lido_eth_staking_contract(self, context: DecoderContext) -> DecodingOutput:
        """Decode interactions with stETH ans wstETH contracts"""

        if (
            context.tx_log.topics[0] not in {
                LIDO_STETH_SUBMITTED,
                LIDO_STETH_TRANSFER_SHARES,
            }
        ):
            return DEFAULT_DECODING_OUTPUT

        if (
            context.tx_log.topics[0] == LIDO_STETH_SUBMITTED and
            self.base.any_tracked([
                hex_or_bytes_to_address(context.tx_log.topics[1]),  # sender address
            ])
        ):
            return self._decode_lido_staking_in_steth(
                context=context,
            )
        elif (  # wsteth supports also the automatic staking with direct ETH transfers
            context.tx_log.topics[0] == LIDO_STETH_SUBMITTED and
            hex_or_bytes_to_address(context.tx_log.topics[1]) == self.wsteth_evm_address  # sender address  # noqa: E501

        ):
            return self._maybe_decode_lido_staking_with_eth_transfer_to_wsteth(
                context=context,
            )
        elif (  # there is no event log emitted for wrap and unwrapping, using TransferShares topic and ERC20 transfers  # noqa: E501
            context.tx_log.topics[0] == LIDO_STETH_TRANSFER_SHARES and
            self.base.any_tracked([
                hex_or_bytes_to_address(context.tx_log.topics[1]),  # from
                hex_or_bytes_to_address(context.tx_log.topics[2]),  # to
            ]) and
            self.wsteth_evm_address in {
                hex_or_bytes_to_address(context.tx_log.topics[1]),  # from
                hex_or_bytes_to_address(context.tx_log.topics[2]),  # to
            }
        ):
            return self._decode_steth_wrap_unwrap(
                context=context,
            )
        else:
            return DEFAULT_DECODING_OUTPUT

    # -- DecoderInterface methods

    def addresses_to_decoders(self) -> dict[ChecksumEvmAddress, tuple[Any, ...]]:
        return {
            self.steth_evm_address: (self._decode_lido_eth_staking_contract,),
            self.wsteth_evm_address: (self._decode_lido_eth_staking_contract,),
            # STETH_WITHDRAWAL_QUEUE_CONTRACT_ADDRESS: (self._decode_steth_withdrawals,),
        }

    def addresses_to_counterparties(self) -> dict['ChecksumEvmAddress', str]:
        return {
            self.steth_evm_address: CPT_LIDO_ETH,
            self.wsteth_evm_address: CPT_LIDO_ETH,
        }

    def post_decoding_rules(self) -> dict[str, list[tuple[int, Callable]]]:
        return {CPT_LIDO_ETH: [(0, self._map_erc20_lido_token_transfer)]}

    @staticmethod
    def counterparties() -> tuple[CounterpartyDetails, ...]:
        return (CounterpartyDetails(identifier=CPT_LIDO_ETH, label='Lido eth', image='lido.svg'),)
