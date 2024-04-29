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

// FactoryContractMetaData contains all meta data concerning the FactoryContract contract.
var FactoryContractMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"at\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"receiver\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"id\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"holder\",\"type\":\"string\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"key\",\"type\":\"uint256\"}],\"name\":\"AssetCreated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"code\",\"type\":\"bytes\"}],\"name\":\"FactoryConstructed\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"assets\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"contracts\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_receiver\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_id\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"_holder\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"_symbol\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"_name\",\"type\":\"string\"}],\"name\":\"deploy\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
}

// FactoryContractABI is the input ABI used to generate the binding from.
// Deprecated: Use FactoryContractMetaData.ABI instead.
var FactoryContractABI = FactoryContractMetaData.ABI

// FactoryContract is an auto generated Go binding around an Ethereum contract.
type FactoryContract struct {
	FactoryContractCaller     // Read-only binding to the contract
	FactoryContractTransactor // Write-only binding to the contract
	FactoryContractFilterer   // Log filterer for contract events
}

// FactoryContractCaller is an auto generated read-only Go binding around an Ethereum contract.
type FactoryContractCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// FactoryContractTransactor is an auto generated write-only Go binding around an Ethereum contract.
type FactoryContractTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// FactoryContractFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type FactoryContractFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// FactoryContractSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type FactoryContractSession struct {
	Contract     *FactoryContract  // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// FactoryContractCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type FactoryContractCallerSession struct {
	Contract *FactoryContractCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts          // Call options to use throughout this session
}

// FactoryContractTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type FactoryContractTransactorSession struct {
	Contract     *FactoryContractTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts          // Transaction auth options to use throughout this session
}

// FactoryContractRaw is an auto generated low-level Go binding around an Ethereum contract.
type FactoryContractRaw struct {
	Contract *FactoryContract // Generic contract binding to access the raw methods on
}

// FactoryContractCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type FactoryContractCallerRaw struct {
	Contract *FactoryContractCaller // Generic read-only contract binding to access the raw methods on
}

// FactoryContractTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type FactoryContractTransactorRaw struct {
	Contract *FactoryContractTransactor // Generic write-only contract binding to access the raw methods on
}

// NewFactoryContract creates a new instance of FactoryContract, bound to a specific deployed contract.
func NewFactoryContract(address common.Address, backend bind.ContractBackend) (*FactoryContract, error) {
	contract, err := bindFactoryContract(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &FactoryContract{FactoryContractCaller: FactoryContractCaller{contract: contract}, FactoryContractTransactor: FactoryContractTransactor{contract: contract}, FactoryContractFilterer: FactoryContractFilterer{contract: contract}}, nil
}

// NewFactoryContractCaller creates a new read-only instance of FactoryContract, bound to a specific deployed contract.
func NewFactoryContractCaller(address common.Address, caller bind.ContractCaller) (*FactoryContractCaller, error) {
	contract, err := bindFactoryContract(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &FactoryContractCaller{contract: contract}, nil
}

// NewFactoryContractTransactor creates a new write-only instance of FactoryContract, bound to a specific deployed contract.
func NewFactoryContractTransactor(address common.Address, transactor bind.ContractTransactor) (*FactoryContractTransactor, error) {
	contract, err := bindFactoryContract(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &FactoryContractTransactor{contract: contract}, nil
}

// NewFactoryContractFilterer creates a new log filterer instance of FactoryContract, bound to a specific deployed contract.
func NewFactoryContractFilterer(address common.Address, filterer bind.ContractFilterer) (*FactoryContractFilterer, error) {
	contract, err := bindFactoryContract(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &FactoryContractFilterer{contract: contract}, nil
}

// bindFactoryContract binds a generic wrapper to an already deployed contract.
func bindFactoryContract(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := FactoryContractMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_FactoryContract *FactoryContractRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _FactoryContract.Contract.FactoryContractCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_FactoryContract *FactoryContractRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _FactoryContract.Contract.FactoryContractTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_FactoryContract *FactoryContractRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _FactoryContract.Contract.FactoryContractTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_FactoryContract *FactoryContractCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _FactoryContract.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_FactoryContract *FactoryContractTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _FactoryContract.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_FactoryContract *FactoryContractTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _FactoryContract.Contract.contract.Transact(opts, method, params...)
}

// Assets is a free data retrieval call binding the contract method 0xf11b8188.
//
// Solidity: function assets(address ) view returns(uint256)
func (_FactoryContract *FactoryContractCaller) Assets(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var out []interface{}
	err := _FactoryContract.contract.Call(opts, &out, "assets", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Assets is a free data retrieval call binding the contract method 0xf11b8188.
//
// Solidity: function assets(address ) view returns(uint256)
func (_FactoryContract *FactoryContractSession) Assets(arg0 common.Address) (*big.Int, error) {
	return _FactoryContract.Contract.Assets(&_FactoryContract.CallOpts, arg0)
}

// Assets is a free data retrieval call binding the contract method 0xf11b8188.
//
// Solidity: function assets(address ) view returns(uint256)
func (_FactoryContract *FactoryContractCallerSession) Assets(arg0 common.Address) (*big.Int, error) {
	return _FactoryContract.Contract.Assets(&_FactoryContract.CallOpts, arg0)
}

// Contracts is a free data retrieval call binding the contract method 0x474da79a.
//
// Solidity: function contracts(uint256 ) view returns(address)
func (_FactoryContract *FactoryContractCaller) Contracts(opts *bind.CallOpts, arg0 *big.Int) (common.Address, error) {
	var out []interface{}
	err := _FactoryContract.contract.Call(opts, &out, "contracts", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Contracts is a free data retrieval call binding the contract method 0x474da79a.
//
// Solidity: function contracts(uint256 ) view returns(address)
func (_FactoryContract *FactoryContractSession) Contracts(arg0 *big.Int) (common.Address, error) {
	return _FactoryContract.Contract.Contracts(&_FactoryContract.CallOpts, arg0)
}

// Contracts is a free data retrieval call binding the contract method 0x474da79a.
//
// Solidity: function contracts(uint256 ) view returns(address)
func (_FactoryContract *FactoryContractCallerSession) Contracts(arg0 *big.Int) (common.Address, error) {
	return _FactoryContract.Contract.Contracts(&_FactoryContract.CallOpts, arg0)
}

// Deploy is a paid mutator transaction binding the contract method 0xbac72406.
//
// Solidity: function deploy(address _receiver, uint256 _id, string _holder, string _symbol, string _name) returns(address)
func (_FactoryContract *FactoryContractTransactor) Deploy(opts *bind.TransactOpts, _receiver common.Address, _id *big.Int, _holder string, _symbol string, _name string) (*types.Transaction, error) {
	return _FactoryContract.contract.Transact(opts, "deploy", _receiver, _id, _holder, _symbol, _name)
}

// Deploy is a paid mutator transaction binding the contract method 0xbac72406.
//
// Solidity: function deploy(address _receiver, uint256 _id, string _holder, string _symbol, string _name) returns(address)
func (_FactoryContract *FactoryContractSession) Deploy(_receiver common.Address, _id *big.Int, _holder string, _symbol string, _name string) (*types.Transaction, error) {
	return _FactoryContract.Contract.Deploy(&_FactoryContract.TransactOpts, _receiver, _id, _holder, _symbol, _name)
}

// Deploy is a paid mutator transaction binding the contract method 0xbac72406.
//
// Solidity: function deploy(address _receiver, uint256 _id, string _holder, string _symbol, string _name) returns(address)
func (_FactoryContract *FactoryContractTransactorSession) Deploy(_receiver common.Address, _id *big.Int, _holder string, _symbol string, _name string) (*types.Transaction, error) {
	return _FactoryContract.Contract.Deploy(&_FactoryContract.TransactOpts, _receiver, _id, _holder, _symbol, _name)
}

// FactoryContractAssetCreatedIterator is returned from FilterAssetCreated and is used to iterate over the raw logs and unpacked data for AssetCreated events raised by the FactoryContract contract.
type FactoryContractAssetCreatedIterator struct {
	Event *FactoryContractAssetCreated // Event containing the contract specifics and raw log

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
func (it *FactoryContractAssetCreatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(FactoryContractAssetCreated)
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
		it.Event = new(FactoryContractAssetCreated)
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
func (it *FactoryContractAssetCreatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *FactoryContractAssetCreatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// FactoryContractAssetCreated represents a AssetCreated event raised by the FactoryContract contract.
type FactoryContractAssetCreated struct {
	At       common.Address
	Receiver common.Address
	Id       *big.Int
	Holder   string
	Key      *big.Int
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterAssetCreated is a free log retrieval operation binding the contract event 0x6712d4854fd77cd7702f970a478ae30ef46d8644066a010e9b14a63447a688ee.
//
// Solidity: event AssetCreated(address indexed at, address receiver, uint256 id, string holder, uint256 key)
func (_FactoryContract *FactoryContractFilterer) FilterAssetCreated(opts *bind.FilterOpts, at []common.Address) (*FactoryContractAssetCreatedIterator, error) {

	var atRule []interface{}
	for _, atItem := range at {
		atRule = append(atRule, atItem)
	}

	logs, sub, err := _FactoryContract.contract.FilterLogs(opts, "AssetCreated", atRule)
	if err != nil {
		return nil, err
	}
	return &FactoryContractAssetCreatedIterator{contract: _FactoryContract.contract, event: "AssetCreated", logs: logs, sub: sub}, nil
}

// WatchAssetCreated is a free log subscription operation binding the contract event 0x6712d4854fd77cd7702f970a478ae30ef46d8644066a010e9b14a63447a688ee.
//
// Solidity: event AssetCreated(address indexed at, address receiver, uint256 id, string holder, uint256 key)
func (_FactoryContract *FactoryContractFilterer) WatchAssetCreated(opts *bind.WatchOpts, sink chan<- *FactoryContractAssetCreated, at []common.Address) (event.Subscription, error) {

	var atRule []interface{}
	for _, atItem := range at {
		atRule = append(atRule, atItem)
	}

	logs, sub, err := _FactoryContract.contract.WatchLogs(opts, "AssetCreated", atRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(FactoryContractAssetCreated)
				if err := _FactoryContract.contract.UnpackLog(event, "AssetCreated", log); err != nil {
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

// ParseAssetCreated is a log parse operation binding the contract event 0x6712d4854fd77cd7702f970a478ae30ef46d8644066a010e9b14a63447a688ee.
//
// Solidity: event AssetCreated(address indexed at, address receiver, uint256 id, string holder, uint256 key)
func (_FactoryContract *FactoryContractFilterer) ParseAssetCreated(log types.Log) (*FactoryContractAssetCreated, error) {
	event := new(FactoryContractAssetCreated)
	if err := _FactoryContract.contract.UnpackLog(event, "AssetCreated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// FactoryContractFactoryConstructedIterator is returned from FilterFactoryConstructed and is used to iterate over the raw logs and unpacked data for FactoryConstructed events raised by the FactoryContract contract.
type FactoryContractFactoryConstructedIterator struct {
	Event *FactoryContractFactoryConstructed // Event containing the contract specifics and raw log

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
func (it *FactoryContractFactoryConstructedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(FactoryContractFactoryConstructed)
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
		it.Event = new(FactoryContractFactoryConstructed)
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
func (it *FactoryContractFactoryConstructedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *FactoryContractFactoryConstructedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// FactoryContractFactoryConstructed represents a FactoryConstructed event raised by the FactoryContract contract.
type FactoryContractFactoryConstructed struct {
	Code []byte
	Raw  types.Log // Blockchain specific contextual infos
}

// FilterFactoryConstructed is a free log retrieval operation binding the contract event 0xfbf94cf8da649b55e37797e65b2ec0ee3ebbadde87490a2352fa257d3590d073.
//
// Solidity: event FactoryConstructed(bytes code)
func (_FactoryContract *FactoryContractFilterer) FilterFactoryConstructed(opts *bind.FilterOpts) (*FactoryContractFactoryConstructedIterator, error) {

	logs, sub, err := _FactoryContract.contract.FilterLogs(opts, "FactoryConstructed")
	if err != nil {
		return nil, err
	}
	return &FactoryContractFactoryConstructedIterator{contract: _FactoryContract.contract, event: "FactoryConstructed", logs: logs, sub: sub}, nil
}

// WatchFactoryConstructed is a free log subscription operation binding the contract event 0xfbf94cf8da649b55e37797e65b2ec0ee3ebbadde87490a2352fa257d3590d073.
//
// Solidity: event FactoryConstructed(bytes code)
func (_FactoryContract *FactoryContractFilterer) WatchFactoryConstructed(opts *bind.WatchOpts, sink chan<- *FactoryContractFactoryConstructed) (event.Subscription, error) {

	logs, sub, err := _FactoryContract.contract.WatchLogs(opts, "FactoryConstructed")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(FactoryContractFactoryConstructed)
				if err := _FactoryContract.contract.UnpackLog(event, "FactoryConstructed", log); err != nil {
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

// ParseFactoryConstructed is a log parse operation binding the contract event 0xfbf94cf8da649b55e37797e65b2ec0ee3ebbadde87490a2352fa257d3590d073.
//
// Solidity: event FactoryConstructed(bytes code)
func (_FactoryContract *FactoryContractFilterer) ParseFactoryConstructed(log types.Log) (*FactoryContractFactoryConstructed, error) {
	event := new(FactoryContractFactoryConstructed)
	if err := _FactoryContract.contract.UnpackLog(event, "FactoryConstructed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
