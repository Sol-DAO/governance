// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {ERC1155} from "solmate/tokens/ERC1155.sol";
import {Owned} from "solmate/auth/Owned.sol";

/// @notice Contract that enables a single call to call multiple methods on itself.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/Multicallable.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/Multicallable.sol)
/// @dev WARNING!
/// Multicallable is NOT SAFE for use in contracts with checks / requires on `msg.value`
/// (e.g. in NFT minting / auction contracts) without a suitable nonce mechanism.
/// It WILL open up your contract to double-spend vulnerabilities / exploits.
/// See: (https://www.paradigm.xyz/2021/08/two-rights-might-make-a-wrong/)
abstract contract Multicallable {
    function multicall(bytes[] calldata data) public payable returns (bytes[] memory results) {
        assembly {
            if data.length {
                results := mload(0x40) // Point `results` to start of free memory.
                mstore(results, data.length) // Store `data.length` into `results`.
                results := add(results, 0x20)

                // `shl` 5 is equivalent to multiplying by 0x20.
                let end := shl(5, data.length)
                // Copy the offsets from calldata into memory.
                calldatacopy(results, data.offset, end)
                // Pointer to the top of the memory (i.e. start of the free memory).
                let memPtr := add(results, end)
                end := add(results, end)

                // prettier-ignore
                for {} 1 {} {
                    // The offset of the current bytes in the calldata.
                    let o := add(data.offset, mload(results))
                    // Copy the current bytes from calldata to the memory.
                    calldatacopy(
                        memPtr,
                        add(o, 0x20), // The offset of the current bytes' bytes.
                        calldataload(o) // The length of the current bytes.
                    )
                    if iszero(delegatecall(gas(), address(), memPtr, calldataload(o), 0x00, 0x00)) {
                        // Bubble up the revert if the delegatecall reverts.
                        returndatacopy(0x00, 0x00, returndatasize())
                        revert(0x00, returndatasize())
                    }
                    // Append the current `memPtr` into `results`.
                    mstore(results, memPtr)
                    results := add(results, 0x20)
                    // Append the `returndatasize()`, and the return data.
                    mstore(memPtr, returndatasize())
                    returndatacopy(add(memPtr, 0x20), 0x00, returndatasize())
                    // Advance the `memPtr` by `returndatasize() + 0x20`,
                    // rounded up to the next multiple of 32.
                    memPtr := and(add(add(memPtr, returndatasize()), 0x3f), 0xffffffffffffffe0)
                    // prettier-ignore
                    if iszero(lt(results, end)) { break }
                }
                // Restore `results` and allocate memory for it.
                results := mload(0x40)
                mstore(0x40, memPtr)
            }
        }
    }
}

/// @notice SolDAO ERC1155 implementation.
/// @author SolDAO (https://github.com/Sol-DAO/governance/blob/main/src/SolDAO.sol)
contract SolDAO is 
    ERC1155, 
    Owned(msg.sender), 
    Multicallable 
{   
    event SetBaseURI(string baseURI);

    event SetURIfetcher(ERC1155 indexed uriFetcher);

    event SetTransferability(uint256 id, bool set);

    string public constant name = "SolDAO";

    string public constant symbol = "SOLD";

    string public baseURI;

    ERC1155 public uriFetcher;

    mapping(uint256 => bool) public transferable;

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) public override {
        require(transferable[id], "NONTRANSFERABLE");

        super.safeTransferFrom(from, to, id, amount, data);
    }

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) public override {
        for (uint256 i; i < ids.length; ) {
            require(transferable[ids[i]], "NONTRANSFERABLE");

            // An array can't have a total length
            // larger than the max uint256 value.
            unchecked {
                ++i;
            }
        }

        super.safeBatchTransferFrom(from, to, ids, amounts, data);
    }

    function mint(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) public payable onlyOwner {
        _mint(to, id, amount, data);
    }

    function burn(
        address from,
        uint256 id,
        uint256 amount
    ) public payable onlyOwner {
        _burn(from, id, amount);
    }

    function uri(uint256 id) public view override returns (string memory) {
        string memory base = baseURI;

        if (bytes(base).length != 0) return string(abi.encodePacked(base, _toString(id)));

        else return uriFetcher.uri(id);
    }

    function _toString(uint256 value) internal pure returns (string memory str) {
        assembly {
            // The maximum value of a uint256 contains 78 digits (1 byte per digit), but
            // we allocate 0xa0 bytes to keep the free memory pointer 32-byte word aligned.
            // We will need 1 word for the trailing zeros padding, 1 word for the length,
            // and 3 words for a maximum of 78 digits. Total: 5 * 0x20 = 0xa0.
            let m := add(mload(0x40), 0xa0)
            // Update the free memory pointer to allocate.
            mstore(0x40, m)
            // Assign the `str` to the end.
            str := sub(m, 0x20)
            // Zeroize the slot after the string.
            mstore(str, 0)

            // Cache the end of the memory to calculate the length later.
            let end := str

            // We write the string from rightmost digit to leftmost digit.
            // The following is essentially a do-while loop that also handles the zero case.
            // prettier-ignore
            for { let temp := value } 1 {} {
                str := sub(str, 1)
                // Write the character to the pointer.
                // The ASCII index of the '0' character is 48.
                mstore8(str, add(48, mod(temp, 10)))
                // Keep dividing `temp` until zero.
                temp := div(temp, 10)
                // prettier-ignore
                if iszero(temp) { break }
            }

            let length := sub(end, str)
            // Move the pointer 32 bytes leftwards to make room for the length.
            str := sub(str, 0x20)
            // Store the length.
            mstore(str, length)
        }
    }

    function setBaseURI(string calldata _baseURI) public payable onlyOwner {
        baseURI = _baseURI;

        emit SetBaseURI(_baseURI);
    }

    function setURIfetcher(ERC1155 _uriFetcher) public payable onlyOwner {
        uriFetcher = _uriFetcher;

        emit SetURIfetcher(_uriFetcher);
    }

    function setTransferability(uint256 id, bool set) public payable onlyOwner {
        transferable[id] = set;

        emit SetTransferability(id, set);
    }
}
