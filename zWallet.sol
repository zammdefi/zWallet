// 0x13e8874aB56f832C11e3Dfe748c0Ec22618c90B5 / 0.0.3

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

interface IERC6909 {
    function setOperator(address spender, bool approved) external returns (bool);
    function isOperator(address owner, address spender) external view returns (bool);
    function balanceOf(address owner, uint256 id) external view returns (uint256);
    function transfer(address to, uint256 id, uint256 amount) external returns (bool);
}

interface IERC721 {
    function ownerOf(uint256 id) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
}

interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// note: Adjust to different blockchains as needed:
address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

// note: These should be same address on every chain:
address constant CTC = 0x0000000000cDC1F8d393415455E382c30FBc0a84; // CheckTheChain.sol
address constant ROUTER = 0x0000000000404FECAf36E6184245475eE1254835; // zRouter.sol

/// @notice Onchain Ethereum Wallet.
contract zWallet {
    string public constant version = "0.0.3";

    constructor() payable {}

    // OWNERSHIP SCANNING:

    function getBalanceOf(address owner, address token, uint256 id)
        public
        view
        returns (uint256 raw, uint256 bal)
    {
        if (token == address(0)) {
            raw = owner.balance;
            bal = raw / 1e18;
        } else if (id == 0) {
            raw = balanceOf(token, owner);
            uint8 dec = MetadataReaderLib.readDecimals(token);
            uint8 safe = dec > 77 ? 77 : dec;
            bal = safe == 0 ? raw : raw / (10 ** uint256(safe));
        } else {
            try IERC6909(token).balanceOf(owner, id) returns (uint256 r) { raw = r; } catch {}
            bal = raw / 1e18;
        }
    }

    function getOwnerOf(IERC721 token, uint256 id) public view returns (address owner) {
        try token.ownerOf(id) returns (address o) { owner = o; } catch {}
    }

    function getMetadata(address token)
        public
        view
        returns (string memory name, string memory symbol, uint8 decimals)
    {
        if (token == address(0)) return ("Ethereum", "ETH", 18);

        name = MetadataReaderLib.readName(token);
        symbol = MetadataReaderLib.readSymbol(token);
        decimals = MetadataReaderLib.readDecimals(token);
    }

    function getAllowanceOf(address owner, IERC20 token, address spender)
        public
        view
        returns (uint256 raw, uint256 allow)
    {
        try token.allowance(owner, spender) returns (uint256 r) {
            raw = r;
        } catch {}

        uint8 dec = MetadataReaderLib.readDecimals(address(token));
        uint8 safe = dec > 77 ? 77 : dec;

        allow = (safe == 0) ? raw : raw / (10 ** uint256(safe));
    }

    function getIsOperatorOf(address owner, IERC6909 token, address spender) public view returns (bool isOperator) {
        try token.isOperator(owner, spender) returns (bool ok) { isOperator = ok; } catch {} 
    }

    // PAYLOAD PREPARATION:

    function isERC721(address token) public view returns (bool ok) {
        try IERC165(token).supportsInterface(0x80ac58cd) returns (bool s) { ok = s; } catch {}
    }

    function isERC6909(address token) public view returns (bool ok) {
        try IERC165(token).supportsInterface(0x0f632fb3) returns (bool s) { ok = s; } catch {}
    }

    function getERC20Approve(address spender, uint256 amount) public pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC20.approve.selector, spender, amount);
    }

    function getERC20Transfer(address to, uint256 amount) public pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC20.transfer.selector, to, amount);
    }

    function getERC6909Transfer(address to, uint256 id, uint256 amount) public pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC6909.transfer.selector, to, id, amount);
    }

    function getERC6909SetOperator(address spender, bool approved) public pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC6909.setOperator.selector, spender, approved);
    }

    function getERC721TransferFrom(address from, address to, uint256 tokenId) public pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC721.transferFrom.selector, from, to, tokenId);
    }

    // ** SWAP HELPERS:

    function checkERC20RouterApproval(address owner, IERC20 token, uint256 amount, bool max)
        public
        view
        returns (bytes memory payload)
    {
        (uint256 raw, ) = getAllowanceOf(owner, token, ROUTER);
        if (raw < amount) {
            return max ? getERC20Approve(ROUTER, type(uint256).max) : getERC20Approve(ROUTER, amount);
        }
    }

    function checkERC6909RouterIsOperator(address owner, IERC6909 token) public view returns (bytes memory payload) {
        if (!getIsOperatorOf(owner, token, ROUTER)) return getERC6909SetOperator(ROUTER, true);
    }

    // PRICE CHECKING:

    function checkPrice(address token)
        public
        view
        returns (uint256 price, string memory priceStr)
    {
        try zWallet(CTC).checkPrice(token) returns (uint256 p, string memory s) {
            return (p, s);
        } catch {}
    }

    function checkPriceInETH(address token)
        public
        view
        returns (uint256 price, string memory priceStr)
    {
        try zWallet(CTC).checkPriceInETH(token) returns (uint256 p, string memory s) {
            return (p, s);
        } catch {}
    }

    function checkPriceInETHToUSDC(address token)
        public
        view
        returns (uint256 price, string memory priceStr)
    {
        try zWallet(CTC).checkPriceInETHToUSDC(token) returns (uint256 p, string memory s) {
            return (p, s);
        } catch {}
    }

    // NAME HANDLING:

    function whatIsTheAddressOf(string calldata name)
        public
        view
        returns (address owner, address receiver, bytes32 node)
    {
        try zWallet(CTC).whatIsTheAddressOf(name) returns (address o, address r, bytes32 n) {
            return (o, r, n);
        } catch {}
    }

    function whatIsTheNameOf(address user)
        public
        view
        returns (string memory ensName)
    {
        try zWallet(CTC).whatIsTheNameOf(user) returns (string memory s) {
            return s;
        } catch {}
    }

    // VIEW BATCHING

    error LengthMismatch();

    /// @notice Minimal, defensive batch view for initializing a wallet UI.
    /// @dev kinds: 0 = ETH, 20 = ERC20-like (id == 0), 72 = ERC721 (flag only), 69 = id-based (e.g. ERC6909).
    /// Price handling:
    /// - ETH (address(0)) & WETH: priceETH = 1e18 & "1"; priceUSDC via WETH (CTC.checkPrice).
    /// - USDC: priceUSDC = 1e6 & "1"; priceETH via CTC.checkPriceInETH(USDC).
    /// - Other ERC20-like: best-effort via CTC; others zero-out.
    function batchView(
        address user,
        address[] calldata tokens,
        uint256[] calldata ids
    ) public view returns (
        string memory ensName,
        address[] memory tokensOut,
        uint256[] memory idsOut,
        uint8[] memory kinds,
        uint256[] memory rawBalances,
        uint256[] memory balances,
        string[] memory names,
        string[] memory symbols,
        uint8[] memory decimals,
        uint256[] memory pricesETH,
        string[] memory pricesETHStr,
        uint256[] memory pricesUSDC,
        string[] memory pricesUSDCStr
    ) {
        uint256 len = tokens.length;
        if (ids.length != len) revert LengthMismatch();

        ensName = whatIsTheNameOf(user);

        tokensOut = new address[](len);
        idsOut = new uint256[](len);
        kinds = new uint8[](len);

        rawBalances = new uint256[](len);
        balances = new uint256[](len);

        names = new string[](len);
        symbols = new string[](len);
        decimals = new uint8[](len);

        pricesETH = new uint256[](len);
        pricesETHStr = new string[](len);
        pricesUSDC = new uint256[](len);
        pricesUSDCStr = new string[](len);

        for (uint256 i; i != len; ++i) {
            address t = tokens[i];
            uint256 id = ids[i];

            tokensOut[i] = t;
            idsOut[i] = id;

            bool isEth = (t == address(0));
            bool isErc20Like = (!isEth && id == 0);

            // Best-effort ERC721 flag via ERC165 (no ownership queries):
            bool is721 = false;
            if (!isEth) {
                try IERC165(t).supportsInterface(0x80ac58cd) returns (bool s) { is721 = s; } catch {}
            }

            // Kind tagging:
            if (isEth) kinds[i] = 0;
            else if (is721) kinds[i] = 72;
            else if (isErc20Like) kinds[i] = 20;
            else kinds[i] = 69;

            // -------- Balances + Metadata (defensive) --------
            if (isEth) {
                uint256 raw = user.balance;
                rawBalances[i] = raw;
                balances[i] = raw / 1e18;
                names[i] = "Ethereum";
                symbols[i] = "ETH";
                decimals[i] = 18;
            } else if (is721) {
                // ERC721: `balanceOf(address)` exists; present as count with 0 decimals:
                uint256 raw = balanceOf(t, user);
                rawBalances[i] = raw;
                balances[i] = raw;
                names[i] = MetadataReaderLib.readName(t);
                symbols[i] = MetadataReaderLib.readSymbol(t);
                decimals[i] = 0;
            } else if (isErc20Like) {
                (string memory nm, string memory sy, uint8 dec) = getMetadata(t);
                uint8 safe = dec > 77 ? 77 : dec; // prevent 10**overflow
                uint256 raw = balanceOf(t, user);
                rawBalances[i] = raw;
                balances[i] = (safe == 0) ? raw : raw / (10 ** uint256(safe));
                names[i] = nm;
                symbols[i] = sy;
                decimals[i] = safe;
            } else {
                // id-based path (e.g. ERC6909). No standard per-id metadata:
                uint256 raw;
                try IERC6909(t).balanceOf(user, id) returns (uint256 r) { raw = r; } catch {}
                rawBalances[i] = raw;
                balances[i] = raw / 1e18; // assume 18 for id-based presentation
                decimals[i] = 18;
            }

            // -------- Prices (special-cased & best-effort) --------
            bool isWeth = (!isEth && t == WETH);          
            bool isUsdc = (!isEth && t == USDC && id == 0);

            if (isEth || isWeth) {
                // 1 ETH = 1 WETH:
                pricesETH[i] = 1e18;
                pricesETHStr[i] = "1";
                // USD quote via WETH:
                try zWallet(CTC).checkPrice(WETH) returns (uint256 a, string memory b) {
                    pricesUSDC[i] = a; pricesUSDCStr[i] = b;
                } catch {}
            } else if (isUsdc) {
                pricesUSDC[i] = 1e6;
                pricesUSDCStr[i] = "1";
                try zWallet(CTC).checkPriceInETH(USDC) returns (uint256 a, string memory b) {
                    pricesETH[i] = a; pricesETHStr[i] = b;
                } catch {}
            } else if (isErc20Like && !is721) {
                uint256 p = 0; string memory ps = "";
                try zWallet(CTC).checkPriceInETH(t) returns (uint256 a1, string memory b1) {
                    p = a1; ps = b1;
                } catch {}
                pricesETH[i] = p; pricesETHStr[i] = ps;

                p = 0; ps = "";
                try zWallet(CTC).checkPriceInETHToUSDC(t) returns (uint256 a2, string memory b2) {
                    p = a2; ps = b2;
                } catch {}
                pricesUSDC[i] = p; pricesUSDCStr[i] = ps;
            }
            // ERC721 and id-based: leave price fields zeroed/empty.
        }
    }
}

/// @notice Library for reading contract metadata robustly.
/// @author Modified from Solady (https://github.com/vectorized/solady/blob/main/src/utils/MetadataReaderLib.sol)
library MetadataReaderLib {
    uint256 constant GAS_STIPEND_NO_GRIEF = 100000;
    uint256 constant STRING_LIMIT_DEFAULT = 1000;

    function readName(address target) internal view returns (string memory) {
        return _string(target, _ptr(0x06fdde03), STRING_LIMIT_DEFAULT, GAS_STIPEND_NO_GRIEF);
    }

    function readSymbol(address target) internal view returns (string memory) {
        return _string(target, _ptr(0x95d89b41), STRING_LIMIT_DEFAULT, GAS_STIPEND_NO_GRIEF);
    }

    function readDecimals(address target) internal view returns (uint8) {
        return uint8(_uint(target, _ptr(0x313ce567), GAS_STIPEND_NO_GRIEF));
    }

    function _string(address target, bytes32 ptr, uint256 limit, uint256 gasStipend)
        private
        view
        returns (string memory result)
    {
        assembly ("memory-safe") {
            function min(x_, y_) -> _z {
                _z := xor(x_, mul(xor(x_, y_), lt(y_, x_)))
            }
            for {} staticcall(gasStipend, target, add(ptr, 0x20), mload(ptr), 0x00, 0x20) {} {
                let m := mload(0x40) 
                let s := add(0x20, m) 
                if iszero(lt(returndatasize(), 0x40)) {
                    let o := mload(0x00)
                    if iszero(gt(o, sub(returndatasize(), 0x20))) {
                        returndatacopy(m, o, 0x20)
                        if iszero(gt(mload(m), sub(returndatasize(), add(o, 0x20)))) {
                            let n := min(mload(m), limit) 
                            mstore(m, n) 
                            returndatacopy(s, add(o, 0x20), n) 
                            mstore(add(s, n), 0) 
                            mstore(0x40, add(0x20, add(s, n)))
                            result := m
                            break
                        }
                    }
                }
                let n := min(returndatasize(), limit) 
                returndatacopy(s, 0, n) 
                mstore8(add(s, n), 0) 
                let i := s 
                for {} byte(0, mload(i)) { i := add(i, 1) } {} 
                mstore(m, sub(i, s)) 
                mstore(i, 0) 
                mstore(0x40, add(0x20, i))
                result := m
                break
            }
        }
    }

    function _uint(address target, bytes32 ptr, uint256 gasStipend)
        private
        view
        returns (uint256 result)
    {
        assembly ("memory-safe") {
            result :=
                mul(
                    mload(0x20),
                    and( 
                        gt(returndatasize(), 0x1f),
                        staticcall(gasStipend, target, add(ptr, 0x20), mload(ptr), 0x20, 0x20)
                    )
                )
        }
    }

    function _ptr(uint256 s) private pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x04, s)
            mstore(result, 4)
        }
    }
}

function balanceOf(address token, address account) view returns (uint256 amount) {
    assembly ("memory-safe") {
        mstore(0x14, account) 
        mstore(0x00, 0x70a08231000000000000000000000000) 
        amount :=
            mul( 
                mload(0x20),
                and( 
                    gt(returndatasize(), 0x1f),
                    staticcall(gas(), token, 0x10, 0x24, 0x20, 0x20)
                )
            )
    }
}
