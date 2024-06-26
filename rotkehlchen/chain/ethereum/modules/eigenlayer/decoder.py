import logging
from typing import Any

from rotkehlchen.accounting.structures.balance import Balance
from rotkehlchen.chain.ethereum.modules.eigenlayer.constants import (
    CPT_EIGENLAYER,
    DELAYED_WITHDRAWALS_CLAIMED,
    DELAYED_WITHDRAWALS_CREATED,
    DEPOSIT_TOPIC,
    EIGEN_TOKEN_ID,
    EIGENLAYER_AIRDROP_DISTRIBUTOR,
    EIGENLAYER_CPT_DETAILS,
    EIGENLAYER_DELEGATION,
    EIGENLAYER_STRATEGY_MANAGER,
    EIGENPOD_DELAYED_WITHDRAWAL_ROUTER,
    EIGENPOD_MANAGER,
    FULL_WITHDRAWAL_REDEEMED,
    OPERATOR_SHARES_INCREASED,
    PARTIAL_WITHDRAWAL_REDEEMED,
    POD_DEPLOYED,
    POD_SHARES_UPDATED,
    WITHDRAWAL_COMPLETE_TOPIC,
)
from rotkehlchen.chain.evm.decoding.clique.decoder import CliqueAirdropDecoderInterface
from rotkehlchen.chain.evm.decoding.structures import (
    DEFAULT_DECODING_OUTPUT,
    DecoderContext,
    DecodingOutput,
)
from rotkehlchen.chain.evm.decoding.types import CounterpartyDetails
from rotkehlchen.constants.assets import A_ETH
from rotkehlchen.constants.resolver import ethaddress_to_identifier
from rotkehlchen.history.events.structures.evm_event import EvmProduct
from rotkehlchen.history.events.structures.types import HistoryEventSubType, HistoryEventType
from rotkehlchen.logging import RotkehlchenLogsAdapter
from rotkehlchen.types import ChecksumEvmAddress
from rotkehlchen.utils.misc import from_wei, hex_or_bytes_to_address, hex_or_bytes_to_int

logger = logging.getLogger(__name__)
log = RotkehlchenLogsAdapter(logger)


class EigenlayerDecoder(CliqueAirdropDecoderInterface):

    def _decode_deposit(self, context: DecoderContext) -> DecodingOutput:
        depositor = hex_or_bytes_to_address(context.tx_log.data[0:32])
        token_addr = hex_or_bytes_to_address(context.tx_log.data[32:64])
        token_identifier = ethaddress_to_identifier(address=token_addr)
        strategy = hex_or_bytes_to_address(context.tx_log.data[64:96])

        for event in context.decoded_events:
            if (
                event.event_type == HistoryEventType.SPEND and
                event.asset == token_identifier and
                event.location_label == depositor
            ):
                event.event_type = HistoryEventType.STAKING
                event.event_subtype = HistoryEventSubType.DEPOSIT_ASSET
                asset = event.asset.resolve_to_crypto_asset()
                event.notes = f'Deposit {event.balance.amount} {asset.symbol} in EigenLayer'
                event.extra_data = {'strategy': strategy}
                event.product = EvmProduct.STAKING
                event.counterparty = CPT_EIGENLAYER

        return DEFAULT_DECODING_OUTPUT

    def _decode_withdrawal(self, context: DecoderContext) -> DecodingOutput:
        """
        Decode withdrawal from eigenlayer. The transaction only contains a transfer event
        and the unstake event but the unstake event doesn't have information about the asset
        or the amount unstaked.
        """
        depositor = hex_or_bytes_to_address(context.tx_log.topics[1])
        withdrawer = hex_or_bytes_to_address(context.tx_log.topics[2])
        depositor_is_tracked = self.base.is_tracked(depositor)
        withdrawer_is_tracked = self.base.is_tracked(withdrawer)

        if depositor_is_tracked is True and withdrawer_is_tracked is True:
            event_type, event_subtype = HistoryEventType.STAKING, HistoryEventSubType.REMOVE_ASSET
            notes = 'Unstake {amount} {symbol} from EigenLayer'
        elif depositor_is_tracked is False and withdrawer_is_tracked is True:  # it is unstake + transfer  # noqa: E501
            event_type, event_subtype = HistoryEventType.RECEIVE, HistoryEventSubType.NONE
            notes = 'Receive {amount} {symbol} from EigenLayer depositor {depositor} unstaking'
        elif depositor_is_tracked is True and withdrawer_is_tracked is False:  # we withdraw to a different address not tracked  # noqa: E501
            notes = 'Send {amount} {symbol} from EigenLayer to {withdrawer} via unstaking'
            event_type, event_subtype = HistoryEventType.SPEND, HistoryEventSubType.NONE
        else:
            log.error(f'Unexpected eigenlayer withdrawal in {context.transaction.tx_hash.hex()}. Skipping')  # noqa: E501
            return DEFAULT_DECODING_OUTPUT

        for event in context.decoded_events:
            if event.event_type == HistoryEventType.RECEIVE:
                event.event_type = event_type
                event.event_subtype = event_subtype
                event.counterparty = CPT_EIGENLAYER
                event.product = EvmProduct.STAKING
                event.notes = notes.format(amount=event.balance.amount, symbol=event.asset.resolve_to_crypto_asset().symbol)  # noqa: E501
                break
        else:
            log.error(f'Could not match eigenlayer withdrawal event in {context.transaction.tx_hash.hex()}')  # noqa: E501

        return DEFAULT_DECODING_OUTPUT

    def decode_event(self, context: DecoderContext) -> DecodingOutput:
        if context.tx_log.topics[0] == DEPOSIT_TOPIC:
            return self._decode_deposit(context)
        elif context.tx_log.topics[0] == WITHDRAWAL_COMPLETE_TOPIC:
            return self._decode_withdrawal(context)

        return DEFAULT_DECODING_OUTPUT

    def decode_airdrop(self, context: DecoderContext) -> DecodingOutput:
        if not (decode_result := self._decode_claim(context)):
            return DEFAULT_DECODING_OUTPUT

        claiming_address, claimed_amount = decode_result
        notes = f'Claim {claimed_amount} EIGEN from the Eigenlayer airdrop'
        for event in context.decoded_events:
            if (
                event.event_type == HistoryEventType.RECEIVE and
                event.location_label == claiming_address and
                event.asset.identifier == EIGEN_TOKEN_ID and
                event.balance.amount == claimed_amount
            ):
                event.event_type = HistoryEventType.RECEIVE
                event.event_subtype = HistoryEventSubType.AIRDROP
                event.counterparty = CPT_EIGENLAYER
                event.notes = notes
                break
        else:
            log.error(f'Could not match eigenlayer airdrop receive event in {context.transaction.tx_hash.hex()}')  # noqa: E501

        return DEFAULT_DECODING_OUTPUT

    def decode_eigenpod_manager_events(self, context: DecoderContext) -> DecodingOutput:
        if context.tx_log.topics[0] == POD_DEPLOYED:
            return self.decode_eigenpod_creation(context)
        elif context.tx_log.topics[0] == POD_SHARES_UPDATED:
            return self.decode_eigenpod_shares_updated(context)

        return DEFAULT_DECODING_OUTPUT

    def decode_eigenpod_shares_updated(self, context: DecoderContext) -> DecodingOutput:
        if not self.base.is_tracked(owner := hex_or_bytes_to_address(context.tx_log.topics[1])):
            return DEFAULT_DECODING_OUTPUT

        shares_delta = hex_or_bytes_to_int(context.tx_log.data[0:32])
        notes = f'{"Restake" if shares_delta > 0 else "Unstake"} {from_wei(shares_delta)} ETH'
        if context.transaction.from_address != owner:
            notes += f' for {owner}'
        event = self.base.make_event_next_index(
            tx_hash=context.transaction.tx_hash,
            timestamp=context.transaction.timestamp,
            event_type=HistoryEventType.INFORMATIONAL,
            event_subtype=HistoryEventSubType.NONE,
            asset=A_ETH,
            balance=Balance(),
            location_label=owner,
            notes=notes,
            counterparty=CPT_EIGENLAYER,
            address=context.tx_log.address,
        )
        return DecodingOutput(event=event)

    def decode_eigenpod_creation(self, context: DecoderContext) -> DecodingOutput:
        if not self.base.is_tracked(owner := hex_or_bytes_to_address(context.tx_log.topics[2])):
            return DEFAULT_DECODING_OUTPUT

        eigenpod_address = hex_or_bytes_to_address(context.tx_log.topics[1])
        suffix = f' with owner {owner}' if context.transaction.from_address != owner else ''
        event = self.base.make_event_next_index(
            tx_hash=context.transaction.tx_hash,
            timestamp=context.transaction.timestamp,
            event_type=HistoryEventType.INFORMATIONAL,
            event_subtype=HistoryEventSubType.CREATE,
            asset=A_ETH,
            balance=Balance(),
            location_label=owner,
            notes=f'Deploy eigenpod {eigenpod_address}{suffix}',
            counterparty=CPT_EIGENLAYER,
            address=context.tx_log.address,
            extra_data={'eigenpod_owner': owner, 'eigenpod_address': eigenpod_address},
        )
        return DecodingOutput(event=event)

    def decode_delayed_withdrawals(self, context: DecoderContext) -> DecodingOutput:
        if context.tx_log.topics[0] == DELAYED_WITHDRAWALS_CREATED:
            return self.decode_delayed_withdrawals_created(context)
        elif context.tx_log.topics[0] == DELAYED_WITHDRAWALS_CLAIMED:
            return self.decode_delayed_withdrawals_claimed(context)

        return DEFAULT_DECODING_OUTPUT

    def decode_delayed_withdrawals_created(self, context: DecoderContext) -> DecodingOutput:
        pod_owner = hex_or_bytes_to_address(context.tx_log.data[0:32])
        recipient = hex_or_bytes_to_address(context.tx_log.data[32:64])
        if not self.base.any_tracked([pod_owner, recipient]):
            return DEFAULT_DECODING_OUTPUT

        amount = from_wei(hex_or_bytes_to_int(context.tx_log.data[64:96]))
        partial_withdrawals_redeemed, full_withdrawals_redeemed = 0, 0
        for log_entry in context.all_logs:
            if log_entry.topics[0] == PARTIAL_WITHDRAWAL_REDEEMED:
                partial_withdrawals_redeemed += 1
            elif log_entry.topics[0] == FULL_WITHDRAWAL_REDEEMED:
                full_withdrawals_redeemed += 1

        notes = f'Start a delayed withdrawal of {amount} ETH from Eigenlayer'
        if partial_withdrawals_redeemed != 0 or full_withdrawals_redeemed != 0:
            notes += f' by processing {partial_withdrawals_redeemed} partial and {full_withdrawals_redeemed} full beaconchain withdrawals'  # noqa: E501
        event = self.base.make_event_next_index(
            tx_hash=context.transaction.tx_hash,
            timestamp=context.transaction.timestamp,
            event_type=HistoryEventType.INFORMATIONAL,
            event_subtype=HistoryEventSubType.NONE,
            asset=A_ETH,
            balance=Balance(),
            location_label=pod_owner,
            notes=notes,
            counterparty=CPT_EIGENLAYER,
            address=context.tx_log.address,
        )
        return DecodingOutput(event=event)

    def decode_delayed_withdrawals_claimed(self, context: DecoderContext) -> DecodingOutput:
        if not self.base.is_tracked(recipient := hex_or_bytes_to_address(context.tx_log.data[0:32])):  # noqa: E501
            return DEFAULT_DECODING_OUTPUT

        amount = from_wei(hex_or_bytes_to_int(context.tx_log.data[32:64]))
        for event in context.decoded_events:
            if (
                    event.event_type == HistoryEventType.RECEIVE and
                    event.asset == A_ETH and
                    event.location_label == recipient and
                    event.balance.amount == amount
            ):  # not sure if TRANSFER/NONE is best match here but
                # since withdrawals are already tracked by validator index
                # at this point we need to make it into an event that counts
                # as transfer between accounts to avoid double counting
                event.event_type = HistoryEventType.TRANSFER
                event.event_subtype = HistoryEventSubType.NONE
                event.notes = f'Claim {event.balance.amount} ETH from Eigenlayer delayed withdrawals'  # noqa: E501
                event.counterparty = CPT_EIGENLAYER

        log.error(f'Did not find matching eigenlayer ETH transfer for delayed withdrawal claim in {context.transaction.tx_hash.hex()}. Skipping')  # noqa: E501

        return DEFAULT_DECODING_OUTPUT

    def decode_delegation(self, context: DecoderContext) -> DecodingOutput:
        if context.tx_log.topics[0] != OPERATOR_SHARES_INCREASED:
            return DEFAULT_DECODING_OUTPUT

        if not self.base.is_tracked(staker := hex_or_bytes_to_address(context.tx_log.data[0:32])):
            return DEFAULT_DECODING_OUTPUT

        operator = hex_or_bytes_to_address(context.tx_log.topics[1])
        shares = hex_or_bytes_to_int(context.tx_log.data[64:96])
        notes = f'Delegate {from_wei(shares)} restaked ETH to {operator}'
        if context.transaction.from_address != staker:
            notes += f' for {staker}'
        event = self.base.make_event_next_index(
            tx_hash=context.transaction.tx_hash,
            timestamp=context.transaction.timestamp,
            event_type=HistoryEventType.INFORMATIONAL,
            event_subtype=HistoryEventSubType.NONE,
            asset=A_ETH,
            balance=Balance(),
            location_label=staker,
            notes=notes,
            counterparty=CPT_EIGENLAYER,
            address=context.tx_log.address,
        )
        return DecodingOutput(event=event)

    # -- DecoderInterface methods

    def addresses_to_decoders(self) -> dict[ChecksumEvmAddress, tuple[Any, ...]]:
        return {
            EIGENLAYER_STRATEGY_MANAGER: (self.decode_event,),
            EIGENLAYER_AIRDROP_DISTRIBUTOR: (self.decode_airdrop,),
            EIGENPOD_MANAGER: (self.decode_eigenpod_manager_events,),
            EIGENPOD_DELAYED_WITHDRAWAL_ROUTER: (self.decode_delayed_withdrawals,),
            EIGENLAYER_DELEGATION: (self.decode_delegation,),
        }

    @staticmethod
    def counterparties() -> tuple[CounterpartyDetails, ...]:
        return (EIGENLAYER_CPT_DETAILS,)

    @staticmethod
    def possible_products() -> dict[str, list[EvmProduct]]:
        return {CPT_EIGENLAYER: [EvmProduct.STAKING]}
