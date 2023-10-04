// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package abi

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// MixinSafeGuardMetaData contains all meta data concerning the MixinSafeGuard contract.
var MixinSafeGuardMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"},{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"name\":\"checkAfterExecution\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"},{\"internalType\":\"enumEnum.Operation\",\"name\":\"operation\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"safeTxGas\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"baseGas\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"gasPrice\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"gasToken\",\"type\":\"address\"},{\"internalType\":\"addresspayable\",\"name\":\"refundReceiver\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"signatures\",\"type\":\"bytes\"},{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"checkTransaction\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"safeAddress\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"observerAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"timelock\",\"type\":\"uint256\"}],\"name\":\"guardSafe\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"safeLastTxTime\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"safeObserver\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"safeTimelock\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

// MixinSafeGuardABI is the input ABI used to generate the binding from.
// Deprecated: Use MixinSafeGuardMetaData.ABI instead.
var MixinSafeGuardABI = MixinSafeGuardMetaData.ABI

// MixinSafeGuard is an auto generated Go binding around an Ethereum contract.
type MixinSafeGuard struct {
	MixinSafeGuardCaller     // Read-only binding to the contract
	MixinSafeGuardTransactor // Write-only binding to the contract
	MixinSafeGuardFilterer   // Log filterer for contract events
}

// MixinSafeGuardCaller is an auto generated read-only Go binding around an Ethereum contract.
type MixinSafeGuardCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MixinSafeGuardTransactor is an auto generated write-only Go binding around an Ethereum contract.
type MixinSafeGuardTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MixinSafeGuardFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type MixinSafeGuardFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MixinSafeGuardSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type MixinSafeGuardSession struct {
	Contract     *MixinSafeGuard   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// MixinSafeGuardCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type MixinSafeGuardCallerSession struct {
	Contract *MixinSafeGuardCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// MixinSafeGuardTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type MixinSafeGuardTransactorSession struct {
	Contract     *MixinSafeGuardTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// MixinSafeGuardRaw is an auto generated low-level Go binding around an Ethereum contract.
type MixinSafeGuardRaw struct {
	Contract *MixinSafeGuard // Generic contract binding to access the raw methods on
}

// MixinSafeGuardCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type MixinSafeGuardCallerRaw struct {
	Contract *MixinSafeGuardCaller // Generic read-only contract binding to access the raw methods on
}

// MixinSafeGuardTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type MixinSafeGuardTransactorRaw struct {
	Contract *MixinSafeGuardTransactor // Generic write-only contract binding to access the raw methods on
}

// NewMixinSafeGuard creates a new instance of MixinSafeGuard, bound to a specific deployed contract.
func NewMixinSafeGuard(address common.Address, backend bind.ContractBackend) (*MixinSafeGuard, error) {
	contract, err := bindMixinSafeGuard(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &MixinSafeGuard{MixinSafeGuardCaller: MixinSafeGuardCaller{contract: contract}, MixinSafeGuardTransactor: MixinSafeGuardTransactor{contract: contract}, MixinSafeGuardFilterer: MixinSafeGuardFilterer{contract: contract}}, nil
}

// NewMixinSafeGuardCaller creates a new read-only instance of MixinSafeGuard, bound to a specific deployed contract.
func NewMixinSafeGuardCaller(address common.Address, caller bind.ContractCaller) (*MixinSafeGuardCaller, error) {
	contract, err := bindMixinSafeGuard(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &MixinSafeGuardCaller{contract: contract}, nil
}

// NewMixinSafeGuardTransactor creates a new write-only instance of MixinSafeGuard, bound to a specific deployed contract.
func NewMixinSafeGuardTransactor(address common.Address, transactor bind.ContractTransactor) (*MixinSafeGuardTransactor, error) {
	contract, err := bindMixinSafeGuard(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &MixinSafeGuardTransactor{contract: contract}, nil
}

// NewMixinSafeGuardFilterer creates a new log filterer instance of MixinSafeGuard, bound to a specific deployed contract.
func NewMixinSafeGuardFilterer(address common.Address, filterer bind.ContractFilterer) (*MixinSafeGuardFilterer, error) {
	contract, err := bindMixinSafeGuard(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &MixinSafeGuardFilterer{contract: contract}, nil
}

// bindMixinSafeGuard binds a generic wrapper to an already deployed contract.
func bindMixinSafeGuard(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := MixinSafeGuardMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_MixinSafeGuard *MixinSafeGuardRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _MixinSafeGuard.Contract.MixinSafeGuardCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_MixinSafeGuard *MixinSafeGuardRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _MixinSafeGuard.Contract.MixinSafeGuardTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_MixinSafeGuard *MixinSafeGuardRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _MixinSafeGuard.Contract.MixinSafeGuardTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_MixinSafeGuard *MixinSafeGuardCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _MixinSafeGuard.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_MixinSafeGuard *MixinSafeGuardTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _MixinSafeGuard.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_MixinSafeGuard *MixinSafeGuardTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _MixinSafeGuard.Contract.contract.Transact(opts, method, params...)
}

// SafeLastTxTime is a free data retrieval call binding the contract method 0xc92fdd71.
//
// Solidity: function safeLastTxTime(address ) view returns(uint256)
func (_MixinSafeGuard *MixinSafeGuardCaller) SafeLastTxTime(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var out []interface{}
	err := _MixinSafeGuard.contract.Call(opts, &out, "safeLastTxTime", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// SafeLastTxTime is a free data retrieval call binding the contract method 0xc92fdd71.
//
// Solidity: function safeLastTxTime(address ) view returns(uint256)
func (_MixinSafeGuard *MixinSafeGuardSession) SafeLastTxTime(arg0 common.Address) (*big.Int, error) {
	return _MixinSafeGuard.Contract.SafeLastTxTime(&_MixinSafeGuard.CallOpts, arg0)
}

// SafeLastTxTime is a free data retrieval call binding the contract method 0xc92fdd71.
//
// Solidity: function safeLastTxTime(address ) view returns(uint256)
func (_MixinSafeGuard *MixinSafeGuardCallerSession) SafeLastTxTime(arg0 common.Address) (*big.Int, error) {
	return _MixinSafeGuard.Contract.SafeLastTxTime(&_MixinSafeGuard.CallOpts, arg0)
}

// SafeObserver is a free data retrieval call binding the contract method 0xa9f99f2f.
//
// Solidity: function safeObserver(address ) view returns(address)
func (_MixinSafeGuard *MixinSafeGuardCaller) SafeObserver(opts *bind.CallOpts, arg0 common.Address) (common.Address, error) {
	var out []interface{}
	err := _MixinSafeGuard.contract.Call(opts, &out, "safeObserver", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// SafeObserver is a free data retrieval call binding the contract method 0xa9f99f2f.
//
// Solidity: function safeObserver(address ) view returns(address)
func (_MixinSafeGuard *MixinSafeGuardSession) SafeObserver(arg0 common.Address) (common.Address, error) {
	return _MixinSafeGuard.Contract.SafeObserver(&_MixinSafeGuard.CallOpts, arg0)
}

// SafeObserver is a free data retrieval call binding the contract method 0xa9f99f2f.
//
// Solidity: function safeObserver(address ) view returns(address)
func (_MixinSafeGuard *MixinSafeGuardCallerSession) SafeObserver(arg0 common.Address) (common.Address, error) {
	return _MixinSafeGuard.Contract.SafeObserver(&_MixinSafeGuard.CallOpts, arg0)
}

// SafeTimelock is a free data retrieval call binding the contract method 0xa67797e5.
//
// Solidity: function safeTimelock(address ) view returns(uint256)
func (_MixinSafeGuard *MixinSafeGuardCaller) SafeTimelock(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var out []interface{}
	err := _MixinSafeGuard.contract.Call(opts, &out, "safeTimelock", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// SafeTimelock is a free data retrieval call binding the contract method 0xa67797e5.
//
// Solidity: function safeTimelock(address ) view returns(uint256)
func (_MixinSafeGuard *MixinSafeGuardSession) SafeTimelock(arg0 common.Address) (*big.Int, error) {
	return _MixinSafeGuard.Contract.SafeTimelock(&_MixinSafeGuard.CallOpts, arg0)
}

// SafeTimelock is a free data retrieval call binding the contract method 0xa67797e5.
//
// Solidity: function safeTimelock(address ) view returns(uint256)
func (_MixinSafeGuard *MixinSafeGuardCallerSession) SafeTimelock(arg0 common.Address) (*big.Int, error) {
	return _MixinSafeGuard.Contract.SafeTimelock(&_MixinSafeGuard.CallOpts, arg0)
}

// CheckAfterExecution is a paid mutator transaction binding the contract method 0x93271368.
//
// Solidity: function checkAfterExecution(bytes32 , bool ) returns()
func (_MixinSafeGuard *MixinSafeGuardTransactor) CheckAfterExecution(opts *bind.TransactOpts, arg0 [32]byte, arg1 bool) (*types.Transaction, error) {
	return _MixinSafeGuard.contract.Transact(opts, "checkAfterExecution", arg0, arg1)
}

// CheckAfterExecution is a paid mutator transaction binding the contract method 0x93271368.
//
// Solidity: function checkAfterExecution(bytes32 , bool ) returns()
func (_MixinSafeGuard *MixinSafeGuardSession) CheckAfterExecution(arg0 [32]byte, arg1 bool) (*types.Transaction, error) {
	return _MixinSafeGuard.Contract.CheckAfterExecution(&_MixinSafeGuard.TransactOpts, arg0, arg1)
}

// CheckAfterExecution is a paid mutator transaction binding the contract method 0x93271368.
//
// Solidity: function checkAfterExecution(bytes32 , bool ) returns()
func (_MixinSafeGuard *MixinSafeGuardTransactorSession) CheckAfterExecution(arg0 [32]byte, arg1 bool) (*types.Transaction, error) {
	return _MixinSafeGuard.Contract.CheckAfterExecution(&_MixinSafeGuard.TransactOpts, arg0, arg1)
}

// CheckTransaction is a paid mutator transaction binding the contract method 0x75f0bb52.
//
// Solidity: function checkTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures, address ) returns()
func (_MixinSafeGuard *MixinSafeGuardTransactor) CheckTransaction(opts *bind.TransactOpts, to common.Address, value *big.Int, data []byte, operation uint8, safeTxGas *big.Int, baseGas *big.Int, gasPrice *big.Int, gasToken common.Address, refundReceiver common.Address, signatures []byte, arg10 common.Address) (*types.Transaction, error) {
	return _MixinSafeGuard.contract.Transact(opts, "checkTransaction", to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures, arg10)
}

// CheckTransaction is a paid mutator transaction binding the contract method 0x75f0bb52.
//
// Solidity: function checkTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures, address ) returns()
func (_MixinSafeGuard *MixinSafeGuardSession) CheckTransaction(to common.Address, value *big.Int, data []byte, operation uint8, safeTxGas *big.Int, baseGas *big.Int, gasPrice *big.Int, gasToken common.Address, refundReceiver common.Address, signatures []byte, arg10 common.Address) (*types.Transaction, error) {
	return _MixinSafeGuard.Contract.CheckTransaction(&_MixinSafeGuard.TransactOpts, to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures, arg10)
}

// CheckTransaction is a paid mutator transaction binding the contract method 0x75f0bb52.
//
// Solidity: function checkTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures, address ) returns()
func (_MixinSafeGuard *MixinSafeGuardTransactorSession) CheckTransaction(to common.Address, value *big.Int, data []byte, operation uint8, safeTxGas *big.Int, baseGas *big.Int, gasPrice *big.Int, gasToken common.Address, refundReceiver common.Address, signatures []byte, arg10 common.Address) (*types.Transaction, error) {
	return _MixinSafeGuard.Contract.CheckTransaction(&_MixinSafeGuard.TransactOpts, to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures, arg10)
}

// GuardSafe is a paid mutator transaction binding the contract method 0xef1f3ced.
//
// Solidity: function guardSafe(address safeAddress, address observerAddress, uint256 timelock) returns()
func (_MixinSafeGuard *MixinSafeGuardTransactor) GuardSafe(opts *bind.TransactOpts, safeAddress common.Address, observerAddress common.Address, timelock *big.Int) (*types.Transaction, error) {
	return _MixinSafeGuard.contract.Transact(opts, "guardSafe", safeAddress, observerAddress, timelock)
}

// GuardSafe is a paid mutator transaction binding the contract method 0xef1f3ced.
//
// Solidity: function guardSafe(address safeAddress, address observerAddress, uint256 timelock) returns()
func (_MixinSafeGuard *MixinSafeGuardSession) GuardSafe(safeAddress common.Address, observerAddress common.Address, timelock *big.Int) (*types.Transaction, error) {
	return _MixinSafeGuard.Contract.GuardSafe(&_MixinSafeGuard.TransactOpts, safeAddress, observerAddress, timelock)
}

// GuardSafe is a paid mutator transaction binding the contract method 0xef1f3ced.
//
// Solidity: function guardSafe(address safeAddress, address observerAddress, uint256 timelock) returns()
func (_MixinSafeGuard *MixinSafeGuardTransactorSession) GuardSafe(safeAddress common.Address, observerAddress common.Address, timelock *big.Int) (*types.Transaction, error) {
	return _MixinSafeGuard.Contract.GuardSafe(&_MixinSafeGuard.TransactOpts, safeAddress, observerAddress, timelock)
}
