// 0xF0cf3dD4A74dA18012Ec3FF83E9794440E80d095 0.0.1

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IERC20 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function allowance(address, address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IERC6909 {
    function balanceOf(address, uint256) external view returns (uint256);
    function transfer(address, uint256, uint256) external returns (bool);
}

interface IERC721 {
    function ownerOf(uint256) external view returns (address);
}

address constant CTC = 0x0000000000cDC1F8d393415455E382c30FBc0a84;

/// @notice Onchain Ethereum Wallet.
contract zWallet {
    string public constant version = "0.0.1";

    constructor() payable {}

    function getBalanceOf(address user, address token, uint256 id)
        public
        view
        returns (uint256 raw, uint256 bal)
    {
        if (token == address(0)) {
            raw = user.balance; bal = raw / 1e18; return (raw, bal);
        }
        if (id == 0) {
            uint8 d = 18;
            try IERC20(token).balanceOf(user) returns (uint256 r) { raw = r; } catch {}
            try IERC20(token).decimals() returns (uint8 dd) { d = dd; } catch {}
            uint8 safe = d > 77 ? 77 : d;
            bal = raw / (10 ** uint256(safe));
        } else {
            try IERC6909(token).balanceOf(user, id) returns (uint256 r) { raw = r; } catch {}
            bal = raw / 1e18; 
        }
    }

    function tryOwnerOf(address token, uint256 id) public view returns (bool ok, address owner) {
        try IERC721(token).ownerOf(id) returns (address o) { return (true, o); }
        catch { return (false, address(0)); }
    }

    function getMetadata(address token)
        public
        view
        returns (string memory name, string memory symbol, uint8 decimals)
    {
        if (token == address(0)) return ("Ethereum", "ETH", 18);

        // best-effort, never revert
        try IERC20(token).name() returns (string memory n) { name = n; } catch {}
        try IERC20(token).symbol() returns (string memory s) { symbol = s; } catch {}
        try IERC20(token).decimals() returns (uint8 d) { decimals = d; } catch { decimals = 18; }
    }

    function getERC20Transfer(address to, uint256 amount) public pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC20.transfer.selector, to, amount);
    }

    function getERC6909Transfer(address to, uint256 id, uint256 amount) public pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC6909.transfer.selector, to, id, amount);
    }

    function checkPriceInETH(address token)
        public
        view
        returns (uint256 price, string memory priceStr)
    {
        return zWallet(CTC).checkPriceInETH(token);
    }

    function checkPriceInETHToUSDC(address token)
        public
        view
        returns (uint256 price, string memory priceStr)
    {
        return zWallet(CTC).checkPriceInETHToUSDC(token);
    }

    error LengthMismatch();

    function batchView(
        address user,
        address[] calldata tokens,
        uint256[] calldata ids
    ) public view returns (
        uint256[] memory rawBalances,
        uint256[] memory balances,
        string[] memory names,
        string[] memory symbols,
        uint8[] memory decimals,
        uint256[] memory pricesETH,
        uint256[] memory pricesUSDC,
        string[] memory pricesETHStr,
        string[] memory pricesUSDCStr
    ) {
        uint256 len = tokens.length;
        require(ids.length == len, LengthMismatch());
        
        rawBalances = new uint256[](len);
        balances = new uint256[](len);
        names = new string[](len);
        symbols = new string[](len);
        decimals = new uint8[](len);
        pricesETH = new uint256[](len);
        pricesUSDC = new uint256[](len);
        pricesETHStr = new string[](len);
        pricesUSDCStr = new string[](len);
        
        for (uint256 i = 0; i < len; ++i) {
            address t = tokens[i];
            uint256 id = ids[i];

            bool isEth = (t == address(0));
            bool isErc20 = (id == 0 && !isEth);

            // -------- Balances + Metadata (defensive) --------
            if (isEth) {
                // ETH
                uint256 raw = user.balance;
                rawBalances[i] = raw;
                balances[i] = raw / 1e18;
                names[i] = "Ethereum";
                symbols[i] = "ETH";
                decimals[i] = 18;
            } else if (isErc20) {
                // ERC-20-ish path (best-effort; never revert)
                uint256 raw;
                // Reuse tolerant metadata reader
                (string memory nm, string memory sy, uint8 dec) = getMetadata(t);

                // balance
                try IERC20(t).balanceOf(user) returns (uint256 r) { raw = r; } catch {}

                // prevent 10**dec overflow, and report the same decimals we used to divide by
                uint8 safe = dec > 77 ? 77 : dec;

                rawBalances[i] = raw;
                balances[i] = raw / (10 ** uint256(safe));
                names[i] = nm;
                symbols[i] = sy;
                decimals[i] = safe; // align reported decimals with divisor used
            } else {
                // 6909 / id-based path (no ERC-20 metadata)
                uint256 raw;
                try IERC6909(t).balanceOf(user, id) returns (uint256 r) { raw = r; } catch {}
                rawBalances[i] = raw;
                balances[i] = raw / 1e18; // assumption for 6909 units
                names[i] = "";            // no standard metadata for 6909 ids
                symbols[i] = "";
                decimals[i] = 18;
            }

            // -------- Prices (defensive; don't block the whole batch) --------
            {
                uint256 p; string memory ps;

                // Price in ETH
                p = 0; ps = "";
                try zWallet(CTC).checkPriceInETH(t) returns (uint256 a, string memory b) {
                    p = a; ps = b;
                } catch {}
                pricesETH[i] = p; pricesETHStr[i] = ps;

                // Price in USDC
                p = 0; ps = "";
                try zWallet(CTC).checkPriceInETHToUSDC(t) returns (uint256 a, string memory b) {
                    p = a; ps = b;
                } catch {}
                pricesUSDC[i] = p; pricesUSDCStr[i] = ps;
            }
        }
    }
}
