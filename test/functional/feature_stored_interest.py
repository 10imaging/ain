#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Copyright (c) DeFi Blockchain Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
"""Test stored interest."""

from test_framework.test_framework import DefiTestFramework

from test_framework.util import assert_equal
from decimal import Decimal
import time

class StoredInterestTest (DefiTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [
            ['-txnotokens=0', '-amkheight=1', '-bayfrontheight=1', '-eunosheight=1', '-fortcanningheight=1', '-fortcanninghillheight=1', '-fortcanningcrunchheight=1', '-greatworldheight=1', '-jellyfish_regtest=1']]

    def run_test(self):
        # Create tokens for tests
        self.setup_test_tokens()

        # Setup pools
        self.setup_test_pools()

        # Setup Oracles
        self.setup_test_oracles()

        # Test token interest changes
        self.test_token_interest_change()

        # Test scheme changes
        self.test_scheme_change()

    def setup_test_tokens(self):
        # Generate chain
        self.nodes[0].generate(120)

        # Get MN address
        self.address = self.nodes[0].get_genesis_keys().ownerAuthAddress

        # Token symbols
        self.symbolDFI = "DFI"
        self.symbolDUSD = "DUSD"

        # Create loan token
        self.nodes[0].setloantoken({
            'symbol': self.symbolDUSD,
            'name': self.symbolDUSD,
            'fixedIntervalPriceId': f"{self.symbolDUSD}/USD",
            'mintable': True,
            'interest': 1
        })
        self.nodes[0].generate(1)

        # Store DUSD ID
        self.idDUSD = list(self.nodes[0].gettoken(self.symbolDUSD).keys())[0]

        # Mint DUSD
        self.nodes[0].minttokens("100000@DUSD")
        self.nodes[0].generate(1)

        # Create DFI tokens
        self.nodes[0].utxostoaccount({self.address: "100000@" + self.symbolDFI})
        self.nodes[0].generate(1)

    def setup_test_pools(self):

        # Create pool pair
        self.nodes[0].createpoolpair({
            "tokenA": self.symbolDFI,
            "tokenB": self.symbolDUSD,
            "commission": 0,
            "status": True,
            "ownerAddress": self.address
        })
        self.nodes[0].generate(1)

        # Add pool liquidity
        self.nodes[0].addpoolliquidity({
            self.address: [
                '10000@' + self.symbolDFI,
                '10000@' + self.symbolDUSD]
            }, self.address)
        self.nodes[0].generate(1)

    def setup_test_oracles(self):

        # Create Oracle address
        oracle_address = self.nodes[0].getnewaddress("", "legacy")

        # Define price feeds
        price_feed = [
            {"currency": "USD", "token": "DFI"}
        ]

        # Appoint Oracle
        oracle = self.nodes[0].appointoracle(oracle_address, price_feed, 10)
        self.nodes[0].generate(1)

        # Set Oracle prices
        oracle_prices = [
            {"currency": "USD", "tokenAmount": f"1@{self.symbolDFI}"},
        ]
        self.nodes[0].setoracledata(oracle, int(time.time()), oracle_prices)
        self.nodes[0].generate(10)

        # Set collateral tokens
        self.nodes[0].setcollateraltoken({
                                    'token': self.symbolDFI,
                                    'factor': 1,
                                    'fixedIntervalPriceId': "DFI/USD"
                                    })
        self.nodes[0].generate(1)

        # Create loan scheme
        self.nodes[0].createloanscheme(100, 1, 'LOAN001')
        self.nodes[0].generate(1)

        # Create loan scheme
        self.nodes[0].createloanscheme(150, 1, 'LOAN002')
        self.nodes[0].generate(1)

    def test_token_interest_change(self):

        # Create vault
        vault_address = self.nodes[0].getnewaddress('', 'legacy')
        vault_id = self.nodes[0].createvault(vault_address, 'LOAN001')
        self.nodes[0].generate(1)

        # Fund vault address
        self.nodes[0].accounttoaccount(self.address, {vault_address: f"10@{self.symbolDFI}"})
        self.nodes[0].generate(1)

        # Deposit DUSD and DFI to vault
        self.nodes[0].deposittovault(vault_id, vault_address, f"10@{self.symbolDFI}")
        self.nodes[0].generate(1)

        # Take DUSD loan
        self.nodes[0].takeloan({ "vaultId": vault_id, "amounts": f"1@{self.symbolDUSD}"})
        self.nodes[0].generate(10)

        # Change token interest to create positive interestToHeight value
        self.nodes[0].setgov({"ATTRIBUTES":{f'v0/token/{self.idDUSD}/loan_minting_interest':'1'}})
        self.nodes[0].generate(1)

        # Check stored interest increased as expected
        stored_interest = self.nodes[0].getstoredinterest(vault_id, self.symbolDUSD)
        assert_equal(stored_interest['interestPerBlock'], '0.000000380517503805175038')
        positive_stored_ipb = Decimal(stored_interest['interestPerBlock'])
        assert_equal(Decimal(stored_interest['interestToHeight']), positive_stored_ipb * 10)
        assert_equal(stored_interest['height'], self.nodes[0].getblockcount())

        # Set negative interest to be inverse of positive interest
        self.nodes[0].setgov({"ATTRIBUTES":{f'v0/token/{self.idDUSD}/loan_minting_interest':'-3'}})
        self.nodes[0].generate(6)

        # Apply again to update stored interest
        self.nodes[0].setgov({"ATTRIBUTES":{f'v0/token/{self.idDUSD}/loan_minting_interest':'-3'}})
        self.nodes[0].generate(10)

        # Check interest is now set to be negative and that interest to height has reduced
        stored_interest = self.nodes[0].getstoredinterest(vault_id, self.symbolDUSD)
        assert_equal(stored_interest['interestPerBlock'], '-0.000000380517503805175038')
        assert_equal(Decimal(stored_interest['interestToHeight']), positive_stored_ipb * 5)
        assert_equal(stored_interest['height'], self.nodes[0].getblockcount() - 9)

        # Apply again to update stored interest
        self.nodes[0].setgov({"ATTRIBUTES":{f'v0/token/{self.idDUSD}/loan_minting_interest':'-3'}})
        self.nodes[0].generate(5)

        # Check interest to height is now negative
        stored_interest = self.nodes[0].getstoredinterest(vault_id, self.symbolDUSD)
        negative_stored_ipb = Decimal(stored_interest['interestPerBlock'])
        assert_equal(stored_interest['interestPerBlock'], '-0.000000380517503805175038')
        assert_equal(Decimal(stored_interest['interestToHeight']), negative_stored_ipb * 5)
        assert_equal(stored_interest['height'], self.nodes[0].getblockcount() - 4)

        # Apply again to update stored interest
        self.nodes[0].setgov({"ATTRIBUTES":{f'v0/token/{self.idDUSD}/loan_minting_interest':'-3'}})
        self.nodes[0].generate(1)

        # Check interest to height has additional negative interest
        stored_interest = self.nodes[0].getstoredinterest(vault_id, self.symbolDUSD)
        assert_equal(stored_interest['interestPerBlock'], '-0.000000380517503805175038')
        assert_equal(Decimal(stored_interest['interestToHeight']), negative_stored_ipb * 10)
        assert_equal(stored_interest['height'], self.nodes[0].getblockcount())

    def test_scheme_change(self):

        # Reset token interest
        self.nodes[0].setgov({"ATTRIBUTES":{f'v0/token/{self.idDUSD}/loan_minting_interest':'1'}})
        self.nodes[0].generate(1)

        # Create vault
        vault_address = self.nodes[0].getnewaddress('', 'legacy')
        vault_id = self.nodes[0].createvault(vault_address, 'LOAN001')
        self.nodes[0].generate(1)

        # Fund vault address
        self.nodes[0].accounttoaccount(self.address, {vault_address: f"10@{self.symbolDFI}"})
        self.nodes[0].generate(1)

        # Deposit DUSD and DFI to vault
        self.nodes[0].deposittovault(vault_id, vault_address, f"10@{self.symbolDFI}")
        self.nodes[0].generate(1)

        # Take DUSD loan
        self.nodes[0].takeloan({ "vaultId": vault_id, "amounts": f"1@{self.symbolDUSD}"})
        self.nodes[0].generate(10)

        # Change vault scheme to create positive interest to height
        self.nodes[0].updatevault(vault_id, {'loanSchemeId': 'LOAN002'})
        self.nodes[0].generate(1)

        # Check vault scheme has actually changed
        vault = self.nodes[0].getvault(vault_id)
        assert_equal(vault['loanSchemeId'], 'LOAN002')

        # Check stored interest increased as expected
        stored_interest = self.nodes[0].getstoredinterest(vault_id, self.symbolDUSD)
        assert_equal(stored_interest['interestPerBlock'], '0.000000380517503805175038')
        positive_stored_ipb = Decimal(stored_interest['interestPerBlock'])
        assert_equal(Decimal(stored_interest['interestToHeight']), positive_stored_ipb * 10)
        assert_equal(stored_interest['height'], self.nodes[0].getblockcount())

        # Set negative interest to be inverse of positive interest
        self.nodes[0].setgov({"ATTRIBUTES":{f'v0/token/{self.idDUSD}/loan_minting_interest':'-3'}})
        self.nodes[0].generate(6)

        # Apply scheme change to update stored interest
        self.nodes[0].updatevault(vault_id, {'loanSchemeId': 'LOAN001'})
        self.nodes[0].generate(10)

        # Check vault scheme has actually changed
        vault = self.nodes[0].getvault(vault_id)
        assert_equal(vault['loanSchemeId'], 'LOAN001')

        # Check interest is now set to be negative and that interest to height has reduced
        stored_interest = self.nodes[0].getstoredinterest(vault_id, self.symbolDUSD)
        assert_equal(stored_interest['interestPerBlock'], '-0.000000380517503805175038')
        assert_equal(Decimal(stored_interest['interestToHeight']), positive_stored_ipb * 5)
        assert_equal(stored_interest['height'], self.nodes[0].getblockcount() - 9)

        # Apply scheme change to update stored interest
        self.nodes[0].updatevault(vault_id, {'loanSchemeId': 'LOAN002'})
        self.nodes[0].generate(5)

        # Check vault scheme has actually changed
        vault = self.nodes[0].getvault(vault_id)
        assert_equal(vault['loanSchemeId'], 'LOAN002')

        # Check interest to height is now negative
        stored_interest = self.nodes[0].getstoredinterest(vault_id, self.symbolDUSD)
        negative_stored_ipb = Decimal(stored_interest['interestPerBlock'])
        assert_equal(stored_interest['interestPerBlock'], '-0.000000380517503805175038')
        assert_equal(Decimal(stored_interest['interestToHeight']), negative_stored_ipb * 5)
        assert_equal(stored_interest['height'], self.nodes[0].getblockcount() - 4)

        # Apply scheme change to update stored interest
        self.nodes[0].updatevault(vault_id, {'loanSchemeId': 'LOAN001'})
        self.nodes[0].generate(1)

        # Check vault scheme has actually changed
        vault = self.nodes[0].getvault(vault_id)
        assert_equal(vault['loanSchemeId'], 'LOAN001')

        # Check interest to height has additional negative interest
        stored_interest = self.nodes[0].getstoredinterest(vault_id, self.symbolDUSD)
        assert_equal(stored_interest['interestPerBlock'], '-0.000000380517503805175038')
        assert_equal(Decimal(stored_interest['interestToHeight']), negative_stored_ipb * 10)
        assert_equal(stored_interest['height'], self.nodes[0].getblockcount())

if __name__ == '__main__':
    StoredInterestTest().main()
