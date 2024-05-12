import pytest

from rotkehlchen.accounting.structures.balance import Balance
from rotkehlchen.chain.ethereum.modules.lido.constants import CPT_LIDO_ETH
from rotkehlchen.chain.evm.constants import ZERO_ADDRESS
from rotkehlchen.chain.evm.decoding.constants import CPT_GAS
from rotkehlchen.constants.assets import A_ETH, A_STETH, A_WSTETH
from rotkehlchen.fval import FVal
from rotkehlchen.history.events.structures.evm_event import EvmEvent
from rotkehlchen.history.events.structures.types import HistoryEventSubType, HistoryEventType
from rotkehlchen.tests.utils.ethereum import get_decoded_events_of_transaction
from rotkehlchen.types import Location, TimestampMS, deserialize_evm_tx_hash


# @pytest.mark.vcr()
@pytest.mark.parametrize('ethereum_accounts', [['0x4C49d4Bd6a571827B4A556a0e1e3071DA6231B9D']])
def test_lido_steth_staking(database, ethereum_inquirer, ethereum_accounts):
    tx_hex = deserialize_evm_tx_hash('0x23a3ee601475424e91bdc0999a780afe57bf37cbcce6d1c09a4dfaaae1765451')  # noqa: E501
    evmhash = deserialize_evm_tx_hash(tx_hex)
    events, _ = get_decoded_events_of_transaction(
        evm_inquirer=ethereum_inquirer,
        database=database,
        tx_hash=tx_hex,
    )
    timestamp = TimestampMS(1710486191000)
    gas_str = '0.002846110430778206'
    amount_deposited_eth_str = '1.12137397'
    amount_minted_steth_str = '1.121373969999999999'
    expected_events = [
        EvmEvent(
            tx_hash=evmhash,
            sequence_index=0,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.SPEND,
            event_subtype=HistoryEventSubType.FEE,
            asset=A_ETH,
            balance=Balance(amount=FVal(gas_str)),
            location_label=ethereum_accounts[0],
            notes=f'Burned {gas_str} ETH for gas',
            counterparty=CPT_GAS,
        ), EvmEvent(
            tx_hash=evmhash,
            sequence_index=1,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.DEPOSIT,
            event_subtype=HistoryEventSubType.DEPOSIT_ASSET,
            asset=A_ETH,
            balance=Balance(FVal(amount_deposited_eth_str)),
            location_label=ethereum_accounts[0],
            notes=f'Submit {amount_deposited_eth_str} {A_ETH.symbol_or_name()} to Lido for receiving {A_STETH.symbol_or_name()} in exchange',  # noqa: E501
            counterparty=CPT_LIDO_ETH,
            address=A_STETH.resolve_to_evm_token().evm_address,
        ), EvmEvent(
            tx_hash=evmhash,
            sequence_index=2,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.RECEIVE,
            event_subtype=HistoryEventSubType.RECEIVE_WRAPPED,
            asset=A_STETH,
            balance=Balance(FVal(amount_minted_steth_str)),
            location_label=ethereum_accounts[0],
            notes=f'Receive {amount_minted_steth_str} {A_STETH.symbol_or_name()} in exchange of the deposited {A_ETH.symbol_or_name()}',  # noqa: E501
            counterparty=CPT_LIDO_ETH,
            address=ZERO_ADDRESS,
            extra_data={'staked_eth': str(amount_deposited_eth_str)},
        ),
    ]
    assert events == expected_events


# @pytest.mark.vcr()
@pytest.mark.parametrize('ethereum_accounts', [['0xB2Ee56C5b3ea514Af584C5e5644E762987bAD772']])
def test_lido_staking_through_wsteth_contract(database, ethereum_inquirer, ethereum_accounts):
    tx_hex = deserialize_evm_tx_hash('0x6c52b908dd32266efdd6157a08a4f3225d735eed7dedd5b6d7549bda8827f891')  # noqa: E501
    evmhash = deserialize_evm_tx_hash(tx_hex)
    events, _ = get_decoded_events_of_transaction(
        evm_inquirer=ethereum_inquirer,
        database=database,
        tx_hash=tx_hex,
    )
    timestamp = TimestampMS(1715513171000)
    gas_str = '0.00047404604684269'
    amount_deposited_eth_str = '0.02917997655771724'
    amount_minted_wsteth_str = '0.025019238010239183'
    temp_ratio_wsteth = '1.16630156944728943372464000039197994067071289921553277859507965180500287601054'  # noqa: E501

    expected_events = [
        EvmEvent(
            tx_hash=evmhash,
            sequence_index=0,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.SPEND,
            event_subtype=HistoryEventSubType.FEE,
            asset=A_ETH,
            balance=Balance(amount=FVal(gas_str)),
            location_label=ethereum_accounts[0],
            notes=f'Burned {gas_str} ETH for gas',
            counterparty=CPT_GAS,
        ), EvmEvent(
            tx_hash=evmhash,
            sequence_index=1,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.DEPOSIT,
            event_subtype=HistoryEventSubType.DEPOSIT_ASSET,
            asset=A_ETH,
            balance=Balance(FVal(amount_deposited_eth_str)),
            location_label=ethereum_accounts[0],
            notes=f'Submit {amount_deposited_eth_str} {A_ETH.symbol_or_name()} to Lido for receiving {A_WSTETH.symbol_or_name()} in exchange at wstETH ratio {temp_ratio_wsteth}',  # noqa: E501
            counterparty=CPT_LIDO_ETH,
            address=A_WSTETH.resolve_to_evm_token().evm_address,
        ), EvmEvent(
            tx_hash=evmhash,
            sequence_index=2,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.RECEIVE,
            event_subtype=HistoryEventSubType.RECEIVE_WRAPPED,
            asset=A_WSTETH,
            balance=Balance(FVal(amount_minted_wsteth_str)),
            location_label=ethereum_accounts[0],
            notes=f'Receive {amount_minted_wsteth_str} {A_WSTETH.symbol_or_name()} in exchange of the deposited {A_ETH.symbol_or_name()} at wstETH ratio {temp_ratio_wsteth}',  # noqa: E501
            counterparty=CPT_LIDO_ETH,
            address=ZERO_ADDRESS,
            extra_data={'staked_eth': str(amount_deposited_eth_str)},
        ),
    ]
    assert events == expected_events


# @pytest.mark.vcr()
@pytest.mark.parametrize('ethereum_accounts', [['0x18AbAf5109018652D30446b89208118d7298E88a']])
def test_lido_steth_wrap_to_wsteth(database, ethereum_inquirer, ethereum_accounts):
    tx_hex = deserialize_evm_tx_hash('0x7292c9a8994c54b521961644b969c6f79461eac8565a298326b2b5af257d34c8')  # noqa: E501
    evmhash = deserialize_evm_tx_hash(tx_hex)
    events, _ = get_decoded_events_of_transaction(
        evm_inquirer=ethereum_inquirer,
        database=database,
        tx_hash=tx_hex,
    )
    timestamp = TimestampMS(1715512475000)
    gas_str = '0.000352480883123694'
    amount_steth_wrapped = '0.28274741654198946'
    amount_minted_wsteth_str = '0.242430794872361797'
    temp_ratio_wsteth = '1.16630156944728946865158665589292545881785507479139160543034074687753152238405'  # noqa: E501

    expected_events = [
        EvmEvent(
            tx_hash=evmhash,
            sequence_index=0,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.SPEND,
            event_subtype=HistoryEventSubType.FEE,
            asset=A_ETH,
            balance=Balance(amount=FVal(gas_str)),
            location_label=ethereum_accounts[0],
            notes=f'Burned {gas_str} ETH for gas',
            counterparty=CPT_GAS,
        ), EvmEvent(
            tx_hash=evmhash,
            sequence_index=225,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.INFORMATIONAL,
            event_subtype=HistoryEventSubType.APPROVE,
            asset=A_STETH,
            balance=Balance(FVal(0)),
            location_label=ethereum_accounts[0],
            notes=f'Revoke stETH spending approval of {ethereum_accounts[0]} by {A_WSTETH.resolve_to_evm_token().evm_address}',  # noqa: E501
            counterparty=None,
            address=A_WSTETH.resolve_to_evm_token().evm_address,
        ), EvmEvent(
            tx_hash=evmhash,
            sequence_index=226,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.DEPOSIT,
            event_subtype=HistoryEventSubType.DEPOSIT_ASSET,
            asset=A_STETH,
            balance=Balance(FVal(amount_steth_wrapped)),
            location_label=ethereum_accounts[0],
            notes=f'Send {amount_steth_wrapped} {A_STETH.symbol_or_name()} for wrapping at wstETH ratio {temp_ratio_wsteth}',  # noqa: E501
            counterparty=CPT_LIDO_ETH,
            address=A_WSTETH.resolve_to_evm_token().evm_address,
        ), EvmEvent(
            tx_hash=evmhash,
            sequence_index=227,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.RECEIVE,
            event_subtype=HistoryEventSubType.RECEIVE_WRAPPED,
            asset=A_WSTETH,
            balance=Balance(FVal(amount_minted_wsteth_str)),
            location_label=ethereum_accounts[0],
            notes=f'Receive {amount_minted_wsteth_str} {A_WSTETH.symbol_or_name()} in exchange of the deposited {A_STETH.symbol_or_name()} at wstETH ratio {temp_ratio_wsteth}',  # noqa: E501
            counterparty=CPT_LIDO_ETH,
            address=ZERO_ADDRESS,
        ),
    ]
    assert events == expected_events


# @pytest.mark.vcr()
@pytest.mark.parametrize('ethereum_accounts', [['0x994b130cEdc9F781360eA37e33bd26CC5E2Aef48']])
def test_lido_wsteth_unwrap_to_steth(database, ethereum_inquirer, ethereum_accounts):
    tx_hex = deserialize_evm_tx_hash('0xcec42b49221f36c7b718ee6c49d90ef4289e78e575a1d1085470d3f25019efd0')  # noqa: E501
    evmhash = deserialize_evm_tx_hash(tx_hex)
    events, _ = get_decoded_events_of_transaction(
        evm_inquirer=ethereum_inquirer,
        database=database,
        tx_hash=tx_hex,
    )
    timestamp = TimestampMS(1715511611000)
    gas_str = '0.000331676530113958'
    amount_unwrapped_wsteth_str = '0.284605729458013827'
    amount_received_steth_str = '0.331936108940572191'
    temp_ratio_wsteth = '1.16630156944728946669004219723386084913782806705522683466439615171015639643417'  # noqa: E501

    expected_events = [
        EvmEvent(
            tx_hash=evmhash,
            sequence_index=0,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.SPEND,
            event_subtype=HistoryEventSubType.FEE,
            asset=A_ETH,
            balance=Balance(amount=FVal(gas_str)),
            location_label=ethereum_accounts[0],
            notes=f'Burned {gas_str} ETH for gas',
            counterparty=CPT_GAS,
        ), EvmEvent(
            tx_hash=evmhash,
            sequence_index=1,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.SPEND,
            event_subtype=HistoryEventSubType.RETURN_WRAPPED,
            asset=A_WSTETH,
            balance=Balance(FVal(amount_unwrapped_wsteth_str)),
            location_label=ethereum_accounts[0],
            notes=f'Send {amount_unwrapped_wsteth_str} {A_WSTETH.symbol_or_name()} for unwrapping at wstETH ratio {temp_ratio_wsteth}',  # noqa: E501
            counterparty=CPT_LIDO_ETH,
            address=ZERO_ADDRESS,
        ), EvmEvent(
            tx_hash=evmhash,
            sequence_index=2,
            timestamp=timestamp,
            location=Location.ETHEREUM,
            event_type=HistoryEventType.WITHDRAWAL,
            event_subtype=HistoryEventSubType.REMOVE_ASSET,
            asset=A_STETH,
            balance=Balance(FVal(amount_received_steth_str)),
            location_label=ethereum_accounts[0],
            notes=f'Receive {amount_received_steth_str} {A_STETH.symbol_or_name()} in exchange of the returned {A_WSTETH.symbol_or_name()} at wstETH ratio {temp_ratio_wsteth}',  # noqa: E501
            counterparty=CPT_LIDO_ETH,
            address=A_WSTETH.resolve_to_evm_token().evm_address,
        ),
    ]
    assert events == expected_events
