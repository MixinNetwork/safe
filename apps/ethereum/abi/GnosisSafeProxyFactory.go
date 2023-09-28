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

// ProxyFactoryMetaData contains all meta data concerning the ProxyFactory contract.
var ProxyFactoryMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"contractGnosisSafeProxy\",\"name\":\"proxy\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"singleton\",\"type\":\"address\"}],\"name\":\"ProxyCreation\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_singleton\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"initializer\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"saltNonce\",\"type\":\"uint256\"}],\"name\":\"calculateCreateProxyWithNonceAddress\",\"outputs\":[{\"internalType\":\"contractGnosisSafeProxy\",\"name\":\"proxy\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"singleton\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"createProxy\",\"outputs\":[{\"internalType\":\"contractGnosisSafeProxy\",\"name\":\"proxy\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_singleton\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"initializer\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"saltNonce\",\"type\":\"uint256\"},{\"internalType\":\"contractIProxyCreationCallback\",\"name\":\"callback\",\"type\":\"address\"}],\"name\":\"createProxyWithCallback\",\"outputs\":[{\"internalType\":\"contractGnosisSafeProxy\",\"name\":\"proxy\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_singleton\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"initializer\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"saltNonce\",\"type\":\"uint256\"}],\"name\":\"createProxyWithNonce\",\"outputs\":[{\"internalType\":\"contractGnosisSafeProxy\",\"name\":\"proxy\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"proxyCreationCode\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"proxyRuntimeCode\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"pure\",\"type\":\"function\"}]",
}

// ProxyFactoryABI is the input ABI used to generate the binding from.
// Deprecated: Use ProxyFactoryMetaData.ABI instead.
var ProxyFactoryABI = ProxyFactoryMetaData.ABI

// ProxyFactory is an auto generated Go binding around an Ethereum contract.
type ProxyFactory struct {
	ProxyFactoryCaller     // Read-only binding to the contract
	ProxyFactoryTransactor // Write-only binding to the contract
	ProxyFactoryFilterer   // Log filterer for contract events
}

// ProxyFactoryCaller is an auto generated read-only Go binding around an Ethereum contract.
type ProxyFactoryCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ProxyFactoryTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ProxyFactoryTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ProxyFactoryFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ProxyFactoryFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ProxyFactorySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ProxyFactorySession struct {
	Contract     *ProxyFactory     // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ProxyFactoryCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ProxyFactoryCallerSession struct {
	Contract *ProxyFactoryCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts       // Call options to use throughout this session
}

// ProxyFactoryTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ProxyFactoryTransactorSession struct {
	Contract     *ProxyFactoryTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts       // Transaction auth options to use throughout this session
}

// ProxyFactoryRaw is an auto generated low-level Go binding around an Ethereum contract.
type ProxyFactoryRaw struct {
	Contract *ProxyFactory // Generic contract binding to access the raw methods on
}

// ProxyFactoryCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ProxyFactoryCallerRaw struct {
	Contract *ProxyFactoryCaller // Generic read-only contract binding to access the raw methods on
}

// ProxyFactoryTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ProxyFactoryTransactorRaw struct {
	Contract *ProxyFactoryTransactor // Generic write-only contract binding to access the raw methods on
}

// NewProxyFactory creates a new instance of ProxyFactory, bound to a specific deployed contract.
func NewProxyFactory(address common.Address, backend bind.ContractBackend) (*ProxyFactory, error) {
	contract, err := bindProxyFactory(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ProxyFactory{ProxyFactoryCaller: ProxyFactoryCaller{contract: contract}, ProxyFactoryTransactor: ProxyFactoryTransactor{contract: contract}, ProxyFactoryFilterer: ProxyFactoryFilterer{contract: contract}}, nil
}

// NewProxyFactoryCaller creates a new read-only instance of ProxyFactory, bound to a specific deployed contract.
func NewProxyFactoryCaller(address common.Address, caller bind.ContractCaller) (*ProxyFactoryCaller, error) {
	contract, err := bindProxyFactory(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ProxyFactoryCaller{contract: contract}, nil
}

// NewProxyFactoryTransactor creates a new write-only instance of ProxyFactory, bound to a specific deployed contract.
func NewProxyFactoryTransactor(address common.Address, transactor bind.ContractTransactor) (*ProxyFactoryTransactor, error) {
	contract, err := bindProxyFactory(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ProxyFactoryTransactor{contract: contract}, nil
}

// NewProxyFactoryFilterer creates a new log filterer instance of ProxyFactory, bound to a specific deployed contract.
func NewProxyFactoryFilterer(address common.Address, filterer bind.ContractFilterer) (*ProxyFactoryFilterer, error) {
	contract, err := bindProxyFactory(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ProxyFactoryFilterer{contract: contract}, nil
}

// bindProxyFactory binds a generic wrapper to an already deployed contract.
func bindProxyFactory(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := ProxyFactoryMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ProxyFactory *ProxyFactoryRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ProxyFactory.Contract.ProxyFactoryCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ProxyFactory *ProxyFactoryRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ProxyFactory.Contract.ProxyFactoryTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ProxyFactory *ProxyFactoryRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ProxyFactory.Contract.ProxyFactoryTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ProxyFactory *ProxyFactoryCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ProxyFactory.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ProxyFactory *ProxyFactoryTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ProxyFactory.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ProxyFactory *ProxyFactoryTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ProxyFactory.Contract.contract.Transact(opts, method, params...)
}

// ProxyCreationCode is a free data retrieval call binding the contract method 0x53e5d935.
//
// Solidity: function proxyCreationCode() pure returns(bytes)
func (_ProxyFactory *ProxyFactoryCaller) ProxyCreationCode(opts *bind.CallOpts) ([]byte, error) {
	var out []interface{}
	err := _ProxyFactory.contract.Call(opts, &out, "proxyCreationCode")

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// ProxyCreationCode is a free data retrieval call binding the contract method 0x53e5d935.
//
// Solidity: function proxyCreationCode() pure returns(bytes)
func (_ProxyFactory *ProxyFactorySession) ProxyCreationCode() ([]byte, error) {
	return _ProxyFactory.Contract.ProxyCreationCode(&_ProxyFactory.CallOpts)
}

// ProxyCreationCode is a free data retrieval call binding the contract method 0x53e5d935.
//
// Solidity: function proxyCreationCode() pure returns(bytes)
func (_ProxyFactory *ProxyFactoryCallerSession) ProxyCreationCode() ([]byte, error) {
	return _ProxyFactory.Contract.ProxyCreationCode(&_ProxyFactory.CallOpts)
}

// ProxyRuntimeCode is a free data retrieval call binding the contract method 0xaddacc0f.
//
// Solidity: function proxyRuntimeCode() pure returns(bytes)
func (_ProxyFactory *ProxyFactoryCaller) ProxyRuntimeCode(opts *bind.CallOpts) ([]byte, error) {
	var out []interface{}
	err := _ProxyFactory.contract.Call(opts, &out, "proxyRuntimeCode")

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// ProxyRuntimeCode is a free data retrieval call binding the contract method 0xaddacc0f.
//
// Solidity: function proxyRuntimeCode() pure returns(bytes)
func (_ProxyFactory *ProxyFactorySession) ProxyRuntimeCode() ([]byte, error) {
	return _ProxyFactory.Contract.ProxyRuntimeCode(&_ProxyFactory.CallOpts)
}

// ProxyRuntimeCode is a free data retrieval call binding the contract method 0xaddacc0f.
//
// Solidity: function proxyRuntimeCode() pure returns(bytes)
func (_ProxyFactory *ProxyFactoryCallerSession) ProxyRuntimeCode() ([]byte, error) {
	return _ProxyFactory.Contract.ProxyRuntimeCode(&_ProxyFactory.CallOpts)
}

// CalculateCreateProxyWithNonceAddress is a paid mutator transaction binding the contract method 0x2500510e.
//
// Solidity: function calculateCreateProxyWithNonceAddress(address _singleton, bytes initializer, uint256 saltNonce) returns(address proxy)
func (_ProxyFactory *ProxyFactoryTransactor) CalculateCreateProxyWithNonceAddress(opts *bind.TransactOpts, _singleton common.Address, initializer []byte, saltNonce *big.Int) (*types.Transaction, error) {
	return _ProxyFactory.contract.Transact(opts, "calculateCreateProxyWithNonceAddress", _singleton, initializer, saltNonce)
}

// CalculateCreateProxyWithNonceAddress is a paid mutator transaction binding the contract method 0x2500510e.
//
// Solidity: function calculateCreateProxyWithNonceAddress(address _singleton, bytes initializer, uint256 saltNonce) returns(address proxy)
func (_ProxyFactory *ProxyFactorySession) CalculateCreateProxyWithNonceAddress(_singleton common.Address, initializer []byte, saltNonce *big.Int) (*types.Transaction, error) {
	return _ProxyFactory.Contract.CalculateCreateProxyWithNonceAddress(&_ProxyFactory.TransactOpts, _singleton, initializer, saltNonce)
}

// CalculateCreateProxyWithNonceAddress is a paid mutator transaction binding the contract method 0x2500510e.
//
// Solidity: function calculateCreateProxyWithNonceAddress(address _singleton, bytes initializer, uint256 saltNonce) returns(address proxy)
func (_ProxyFactory *ProxyFactoryTransactorSession) CalculateCreateProxyWithNonceAddress(_singleton common.Address, initializer []byte, saltNonce *big.Int) (*types.Transaction, error) {
	return _ProxyFactory.Contract.CalculateCreateProxyWithNonceAddress(&_ProxyFactory.TransactOpts, _singleton, initializer, saltNonce)
}

// CreateProxy is a paid mutator transaction binding the contract method 0x61b69abd.
//
// Solidity: function createProxy(address singleton, bytes data) returns(address proxy)
func (_ProxyFactory *ProxyFactoryTransactor) CreateProxy(opts *bind.TransactOpts, singleton common.Address, data []byte) (*types.Transaction, error) {
	return _ProxyFactory.contract.Transact(opts, "createProxy", singleton, data)
}

// CreateProxy is a paid mutator transaction binding the contract method 0x61b69abd.
//
// Solidity: function createProxy(address singleton, bytes data) returns(address proxy)
func (_ProxyFactory *ProxyFactorySession) CreateProxy(singleton common.Address, data []byte) (*types.Transaction, error) {
	return _ProxyFactory.Contract.CreateProxy(&_ProxyFactory.TransactOpts, singleton, data)
}

// CreateProxy is a paid mutator transaction binding the contract method 0x61b69abd.
//
// Solidity: function createProxy(address singleton, bytes data) returns(address proxy)
func (_ProxyFactory *ProxyFactoryTransactorSession) CreateProxy(singleton common.Address, data []byte) (*types.Transaction, error) {
	return _ProxyFactory.Contract.CreateProxy(&_ProxyFactory.TransactOpts, singleton, data)
}

// CreateProxyWithCallback is a paid mutator transaction binding the contract method 0xd18af54d.
//
// Solidity: function createProxyWithCallback(address _singleton, bytes initializer, uint256 saltNonce, address callback) returns(address proxy)
func (_ProxyFactory *ProxyFactoryTransactor) CreateProxyWithCallback(opts *bind.TransactOpts, _singleton common.Address, initializer []byte, saltNonce *big.Int, callback common.Address) (*types.Transaction, error) {
	return _ProxyFactory.contract.Transact(opts, "createProxyWithCallback", _singleton, initializer, saltNonce, callback)
}

// CreateProxyWithCallback is a paid mutator transaction binding the contract method 0xd18af54d.
//
// Solidity: function createProxyWithCallback(address _singleton, bytes initializer, uint256 saltNonce, address callback) returns(address proxy)
func (_ProxyFactory *ProxyFactorySession) CreateProxyWithCallback(_singleton common.Address, initializer []byte, saltNonce *big.Int, callback common.Address) (*types.Transaction, error) {
	return _ProxyFactory.Contract.CreateProxyWithCallback(&_ProxyFactory.TransactOpts, _singleton, initializer, saltNonce, callback)
}

// CreateProxyWithCallback is a paid mutator transaction binding the contract method 0xd18af54d.
//
// Solidity: function createProxyWithCallback(address _singleton, bytes initializer, uint256 saltNonce, address callback) returns(address proxy)
func (_ProxyFactory *ProxyFactoryTransactorSession) CreateProxyWithCallback(_singleton common.Address, initializer []byte, saltNonce *big.Int, callback common.Address) (*types.Transaction, error) {
	return _ProxyFactory.Contract.CreateProxyWithCallback(&_ProxyFactory.TransactOpts, _singleton, initializer, saltNonce, callback)
}

// CreateProxyWithNonce is a paid mutator transaction binding the contract method 0x1688f0b9.
//
// Solidity: function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns(address proxy)
func (_ProxyFactory *ProxyFactoryTransactor) CreateProxyWithNonce(opts *bind.TransactOpts, _singleton common.Address, initializer []byte, saltNonce *big.Int) (*types.Transaction, error) {
	return _ProxyFactory.contract.Transact(opts, "createProxyWithNonce", _singleton, initializer, saltNonce)
}

// CreateProxyWithNonce is a paid mutator transaction binding the contract method 0x1688f0b9.
//
// Solidity: function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns(address proxy)
func (_ProxyFactory *ProxyFactorySession) CreateProxyWithNonce(_singleton common.Address, initializer []byte, saltNonce *big.Int) (*types.Transaction, error) {
	return _ProxyFactory.Contract.CreateProxyWithNonce(&_ProxyFactory.TransactOpts, _singleton, initializer, saltNonce)
}

// CreateProxyWithNonce is a paid mutator transaction binding the contract method 0x1688f0b9.
//
// Solidity: function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns(address proxy)
func (_ProxyFactory *ProxyFactoryTransactorSession) CreateProxyWithNonce(_singleton common.Address, initializer []byte, saltNonce *big.Int) (*types.Transaction, error) {
	return _ProxyFactory.Contract.CreateProxyWithNonce(&_ProxyFactory.TransactOpts, _singleton, initializer, saltNonce)
}

// ProxyFactoryProxyCreationIterator is returned from FilterProxyCreation and is used to iterate over the raw logs and unpacked data for ProxyCreation events raised by the ProxyFactory contract.
type ProxyFactoryProxyCreationIterator struct {
	Event *ProxyFactoryProxyCreation // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ProxyFactoryProxyCreationIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ProxyFactoryProxyCreation)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ProxyFactoryProxyCreation)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ProxyFactoryProxyCreationIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ProxyFactoryProxyCreationIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ProxyFactoryProxyCreation represents a ProxyCreation event raised by the ProxyFactory contract.
type ProxyFactoryProxyCreation struct {
	Proxy     common.Address
	Singleton common.Address
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterProxyCreation is a free log retrieval operation binding the contract event 0x4f51faf6c4561ff95f067657e43439f0f856d97c04d9ec9070a6199ad418e235.
//
// Solidity: event ProxyCreation(address proxy, address singleton)
func (_ProxyFactory *ProxyFactoryFilterer) FilterProxyCreation(opts *bind.FilterOpts) (*ProxyFactoryProxyCreationIterator, error) {

	logs, sub, err := _ProxyFactory.contract.FilterLogs(opts, "ProxyCreation")
	if err != nil {
		return nil, err
	}
	return &ProxyFactoryProxyCreationIterator{contract: _ProxyFactory.contract, event: "ProxyCreation", logs: logs, sub: sub}, nil
}

// WatchProxyCreation is a free log subscription operation binding the contract event 0x4f51faf6c4561ff95f067657e43439f0f856d97c04d9ec9070a6199ad418e235.
//
// Solidity: event ProxyCreation(address proxy, address singleton)
func (_ProxyFactory *ProxyFactoryFilterer) WatchProxyCreation(opts *bind.WatchOpts, sink chan<- *ProxyFactoryProxyCreation) (event.Subscription, error) {

	logs, sub, err := _ProxyFactory.contract.WatchLogs(opts, "ProxyCreation")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ProxyFactoryProxyCreation)
				if err := _ProxyFactory.contract.UnpackLog(event, "ProxyCreation", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseProxyCreation is a log parse operation binding the contract event 0x4f51faf6c4561ff95f067657e43439f0f856d97c04d9ec9070a6199ad418e235.
//
// Solidity: event ProxyCreation(address proxy, address singleton)
func (_ProxyFactory *ProxyFactoryFilterer) ParseProxyCreation(log types.Log) (*ProxyFactoryProxyCreation, error) {
	event := new(ProxyFactoryProxyCreation)
	if err := _ProxyFactory.contract.UnpackLog(event, "ProxyCreation", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
