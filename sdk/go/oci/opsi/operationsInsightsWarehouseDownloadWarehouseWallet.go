// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package opsi

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Operations Insights Warehouse Download Warehouse Wallet resource in Oracle Cloud Infrastructure Opsi service.
//
// Download the ADW wallet for Operations Insights Warehouse using which the Hub data is exposed.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Opsi"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Opsi.NewOperationsInsightsWarehouseDownloadWarehouseWallet(ctx, "testOperationsInsightsWarehouseDownloadWarehouseWallet", &Opsi.OperationsInsightsWarehouseDownloadWarehouseWalletArgs{
//				OperationsInsightsWarehouseId:             pulumi.Any(oci_opsi_operations_insights_warehouse.Test_operations_insights_warehouse.Id),
//				OperationsInsightsWarehouseWalletPassword: pulumi.Any(_var.Operations_insights_warehouse_download_warehouse_wallet_operations_insights_warehouse_wallet_password),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// OperationsInsightsWarehouseDownloadWarehouseWallet can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Opsi/operationsInsightsWarehouseDownloadWarehouseWallet:OperationsInsightsWarehouseDownloadWarehouseWallet test_operations_insights_warehouse_download_warehouse_wallet "id"
//
// ```
type OperationsInsightsWarehouseDownloadWarehouseWallet struct {
	pulumi.CustomResourceState

	// Unique Operations Insights Warehouse identifier
	OperationsInsightsWarehouseId pulumi.StringOutput `pulumi:"operationsInsightsWarehouseId"`
	// User provided ADW wallet password for the Operations Insights Warehouse.
	OperationsInsightsWarehouseWalletPassword pulumi.StringOutput `pulumi:"operationsInsightsWarehouseWalletPassword"`
}

// NewOperationsInsightsWarehouseDownloadWarehouseWallet registers a new resource with the given unique name, arguments, and options.
func NewOperationsInsightsWarehouseDownloadWarehouseWallet(ctx *pulumi.Context,
	name string, args *OperationsInsightsWarehouseDownloadWarehouseWalletArgs, opts ...pulumi.ResourceOption) (*OperationsInsightsWarehouseDownloadWarehouseWallet, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.OperationsInsightsWarehouseId == nil {
		return nil, errors.New("invalid value for required argument 'OperationsInsightsWarehouseId'")
	}
	if args.OperationsInsightsWarehouseWalletPassword == nil {
		return nil, errors.New("invalid value for required argument 'OperationsInsightsWarehouseWalletPassword'")
	}
	var resource OperationsInsightsWarehouseDownloadWarehouseWallet
	err := ctx.RegisterResource("oci:Opsi/operationsInsightsWarehouseDownloadWarehouseWallet:OperationsInsightsWarehouseDownloadWarehouseWallet", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetOperationsInsightsWarehouseDownloadWarehouseWallet gets an existing OperationsInsightsWarehouseDownloadWarehouseWallet resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetOperationsInsightsWarehouseDownloadWarehouseWallet(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *OperationsInsightsWarehouseDownloadWarehouseWalletState, opts ...pulumi.ResourceOption) (*OperationsInsightsWarehouseDownloadWarehouseWallet, error) {
	var resource OperationsInsightsWarehouseDownloadWarehouseWallet
	err := ctx.ReadResource("oci:Opsi/operationsInsightsWarehouseDownloadWarehouseWallet:OperationsInsightsWarehouseDownloadWarehouseWallet", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering OperationsInsightsWarehouseDownloadWarehouseWallet resources.
type operationsInsightsWarehouseDownloadWarehouseWalletState struct {
	// Unique Operations Insights Warehouse identifier
	OperationsInsightsWarehouseId *string `pulumi:"operationsInsightsWarehouseId"`
	// User provided ADW wallet password for the Operations Insights Warehouse.
	OperationsInsightsWarehouseWalletPassword *string `pulumi:"operationsInsightsWarehouseWalletPassword"`
}

type OperationsInsightsWarehouseDownloadWarehouseWalletState struct {
	// Unique Operations Insights Warehouse identifier
	OperationsInsightsWarehouseId pulumi.StringPtrInput
	// User provided ADW wallet password for the Operations Insights Warehouse.
	OperationsInsightsWarehouseWalletPassword pulumi.StringPtrInput
}

func (OperationsInsightsWarehouseDownloadWarehouseWalletState) ElementType() reflect.Type {
	return reflect.TypeOf((*operationsInsightsWarehouseDownloadWarehouseWalletState)(nil)).Elem()
}

type operationsInsightsWarehouseDownloadWarehouseWalletArgs struct {
	// Unique Operations Insights Warehouse identifier
	OperationsInsightsWarehouseId string `pulumi:"operationsInsightsWarehouseId"`
	// User provided ADW wallet password for the Operations Insights Warehouse.
	OperationsInsightsWarehouseWalletPassword string `pulumi:"operationsInsightsWarehouseWalletPassword"`
}

// The set of arguments for constructing a OperationsInsightsWarehouseDownloadWarehouseWallet resource.
type OperationsInsightsWarehouseDownloadWarehouseWalletArgs struct {
	// Unique Operations Insights Warehouse identifier
	OperationsInsightsWarehouseId pulumi.StringInput
	// User provided ADW wallet password for the Operations Insights Warehouse.
	OperationsInsightsWarehouseWalletPassword pulumi.StringInput
}

func (OperationsInsightsWarehouseDownloadWarehouseWalletArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*operationsInsightsWarehouseDownloadWarehouseWalletArgs)(nil)).Elem()
}

type OperationsInsightsWarehouseDownloadWarehouseWalletInput interface {
	pulumi.Input

	ToOperationsInsightsWarehouseDownloadWarehouseWalletOutput() OperationsInsightsWarehouseDownloadWarehouseWalletOutput
	ToOperationsInsightsWarehouseDownloadWarehouseWalletOutputWithContext(ctx context.Context) OperationsInsightsWarehouseDownloadWarehouseWalletOutput
}

func (*OperationsInsightsWarehouseDownloadWarehouseWallet) ElementType() reflect.Type {
	return reflect.TypeOf((**OperationsInsightsWarehouseDownloadWarehouseWallet)(nil)).Elem()
}

func (i *OperationsInsightsWarehouseDownloadWarehouseWallet) ToOperationsInsightsWarehouseDownloadWarehouseWalletOutput() OperationsInsightsWarehouseDownloadWarehouseWalletOutput {
	return i.ToOperationsInsightsWarehouseDownloadWarehouseWalletOutputWithContext(context.Background())
}

func (i *OperationsInsightsWarehouseDownloadWarehouseWallet) ToOperationsInsightsWarehouseDownloadWarehouseWalletOutputWithContext(ctx context.Context) OperationsInsightsWarehouseDownloadWarehouseWalletOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OperationsInsightsWarehouseDownloadWarehouseWalletOutput)
}

// OperationsInsightsWarehouseDownloadWarehouseWalletArrayInput is an input type that accepts OperationsInsightsWarehouseDownloadWarehouseWalletArray and OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput values.
// You can construct a concrete instance of `OperationsInsightsWarehouseDownloadWarehouseWalletArrayInput` via:
//
//	OperationsInsightsWarehouseDownloadWarehouseWalletArray{ OperationsInsightsWarehouseDownloadWarehouseWalletArgs{...} }
type OperationsInsightsWarehouseDownloadWarehouseWalletArrayInput interface {
	pulumi.Input

	ToOperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput() OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput
	ToOperationsInsightsWarehouseDownloadWarehouseWalletArrayOutputWithContext(context.Context) OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput
}

type OperationsInsightsWarehouseDownloadWarehouseWalletArray []OperationsInsightsWarehouseDownloadWarehouseWalletInput

func (OperationsInsightsWarehouseDownloadWarehouseWalletArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OperationsInsightsWarehouseDownloadWarehouseWallet)(nil)).Elem()
}

func (i OperationsInsightsWarehouseDownloadWarehouseWalletArray) ToOperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput() OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput {
	return i.ToOperationsInsightsWarehouseDownloadWarehouseWalletArrayOutputWithContext(context.Background())
}

func (i OperationsInsightsWarehouseDownloadWarehouseWalletArray) ToOperationsInsightsWarehouseDownloadWarehouseWalletArrayOutputWithContext(ctx context.Context) OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput)
}

// OperationsInsightsWarehouseDownloadWarehouseWalletMapInput is an input type that accepts OperationsInsightsWarehouseDownloadWarehouseWalletMap and OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput values.
// You can construct a concrete instance of `OperationsInsightsWarehouseDownloadWarehouseWalletMapInput` via:
//
//	OperationsInsightsWarehouseDownloadWarehouseWalletMap{ "key": OperationsInsightsWarehouseDownloadWarehouseWalletArgs{...} }
type OperationsInsightsWarehouseDownloadWarehouseWalletMapInput interface {
	pulumi.Input

	ToOperationsInsightsWarehouseDownloadWarehouseWalletMapOutput() OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput
	ToOperationsInsightsWarehouseDownloadWarehouseWalletMapOutputWithContext(context.Context) OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput
}

type OperationsInsightsWarehouseDownloadWarehouseWalletMap map[string]OperationsInsightsWarehouseDownloadWarehouseWalletInput

func (OperationsInsightsWarehouseDownloadWarehouseWalletMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OperationsInsightsWarehouseDownloadWarehouseWallet)(nil)).Elem()
}

func (i OperationsInsightsWarehouseDownloadWarehouseWalletMap) ToOperationsInsightsWarehouseDownloadWarehouseWalletMapOutput() OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput {
	return i.ToOperationsInsightsWarehouseDownloadWarehouseWalletMapOutputWithContext(context.Background())
}

func (i OperationsInsightsWarehouseDownloadWarehouseWalletMap) ToOperationsInsightsWarehouseDownloadWarehouseWalletMapOutputWithContext(ctx context.Context) OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput)
}

type OperationsInsightsWarehouseDownloadWarehouseWalletOutput struct{ *pulumi.OutputState }

func (OperationsInsightsWarehouseDownloadWarehouseWalletOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**OperationsInsightsWarehouseDownloadWarehouseWallet)(nil)).Elem()
}

func (o OperationsInsightsWarehouseDownloadWarehouseWalletOutput) ToOperationsInsightsWarehouseDownloadWarehouseWalletOutput() OperationsInsightsWarehouseDownloadWarehouseWalletOutput {
	return o
}

func (o OperationsInsightsWarehouseDownloadWarehouseWalletOutput) ToOperationsInsightsWarehouseDownloadWarehouseWalletOutputWithContext(ctx context.Context) OperationsInsightsWarehouseDownloadWarehouseWalletOutput {
	return o
}

// Unique Operations Insights Warehouse identifier
func (o OperationsInsightsWarehouseDownloadWarehouseWalletOutput) OperationsInsightsWarehouseId() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseDownloadWarehouseWallet) pulumi.StringOutput {
		return v.OperationsInsightsWarehouseId
	}).(pulumi.StringOutput)
}

// User provided ADW wallet password for the Operations Insights Warehouse.
func (o OperationsInsightsWarehouseDownloadWarehouseWalletOutput) OperationsInsightsWarehouseWalletPassword() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseDownloadWarehouseWallet) pulumi.StringOutput {
		return v.OperationsInsightsWarehouseWalletPassword
	}).(pulumi.StringOutput)
}

type OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput struct{ *pulumi.OutputState }

func (OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OperationsInsightsWarehouseDownloadWarehouseWallet)(nil)).Elem()
}

func (o OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput) ToOperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput() OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput {
	return o
}

func (o OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput) ToOperationsInsightsWarehouseDownloadWarehouseWalletArrayOutputWithContext(ctx context.Context) OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput {
	return o
}

func (o OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput) Index(i pulumi.IntInput) OperationsInsightsWarehouseDownloadWarehouseWalletOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *OperationsInsightsWarehouseDownloadWarehouseWallet {
		return vs[0].([]*OperationsInsightsWarehouseDownloadWarehouseWallet)[vs[1].(int)]
	}).(OperationsInsightsWarehouseDownloadWarehouseWalletOutput)
}

type OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput struct{ *pulumi.OutputState }

func (OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OperationsInsightsWarehouseDownloadWarehouseWallet)(nil)).Elem()
}

func (o OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput) ToOperationsInsightsWarehouseDownloadWarehouseWalletMapOutput() OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput {
	return o
}

func (o OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput) ToOperationsInsightsWarehouseDownloadWarehouseWalletMapOutputWithContext(ctx context.Context) OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput {
	return o
}

func (o OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput) MapIndex(k pulumi.StringInput) OperationsInsightsWarehouseDownloadWarehouseWalletOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *OperationsInsightsWarehouseDownloadWarehouseWallet {
		return vs[0].(map[string]*OperationsInsightsWarehouseDownloadWarehouseWallet)[vs[1].(string)]
	}).(OperationsInsightsWarehouseDownloadWarehouseWalletOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*OperationsInsightsWarehouseDownloadWarehouseWalletInput)(nil)).Elem(), &OperationsInsightsWarehouseDownloadWarehouseWallet{})
	pulumi.RegisterInputType(reflect.TypeOf((*OperationsInsightsWarehouseDownloadWarehouseWalletArrayInput)(nil)).Elem(), OperationsInsightsWarehouseDownloadWarehouseWalletArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*OperationsInsightsWarehouseDownloadWarehouseWalletMapInput)(nil)).Elem(), OperationsInsightsWarehouseDownloadWarehouseWalletMap{})
	pulumi.RegisterOutputType(OperationsInsightsWarehouseDownloadWarehouseWalletOutput{})
	pulumi.RegisterOutputType(OperationsInsightsWarehouseDownloadWarehouseWalletArrayOutput{})
	pulumi.RegisterOutputType(OperationsInsightsWarehouseDownloadWarehouseWalletMapOutput{})
}