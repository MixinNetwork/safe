// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {Asset} from "./Asset.sol";

contract Factory {
    event FactoryConstructed(bytes code);

    event AssetCreated(
        address indexed at,
        address receiver,
        uint256 id,
        string holder,
        uint256 key
    );

    mapping(address => uint256) public assets;
    mapping(uint256 => address) public contracts;

    constructor() {
        bytes memory code = type(Asset).creationCode;
        emit FactoryConstructed(code);
    }

    function deploy(
        address _receiver,
        uint256 _id,
        string memory _holder,
        string memory _symbol,
        string memory _name
    ) public returns (address) {
        bytes memory args = abi.encodePacked(_receiver, _id, _holder, _symbol, _name);
        uint256 key = uint256(keccak256(args));
        address old = contracts[key];
        if (old != address(0)) {
            return old;
        }

        Asset asset = new Asset{salt: bytes32(key)}(_symbol, _name);
        asset.transfer(_receiver, asset.totalSupply());
        address addr = address(asset);
        assets[addr] = _id;
        contracts[key] = addr;
        emit AssetCreated(addr, _receiver, _id, _holder, key);
        return addr;
    }
}
