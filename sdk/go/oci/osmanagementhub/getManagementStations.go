// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagementhub

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides the list of Management Stations in Oracle Cloud Infrastructure Os Management Hub service.
//
// Lists management stations in a compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/OsManagementHub"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := OsManagementHub.GetManagementStations(ctx, &osmanagementhub.GetManagementStationsArgs{
//				CompartmentId:       pulumi.StringRef(_var.Compartment_id),
//				DisplayName:         pulumi.StringRef(_var.Management_station_display_name),
//				DisplayNameContains: pulumi.StringRef(_var.Management_station_display_name_contains),
//				Id:                  pulumi.StringRef(_var.Management_station_id),
//				ManagedInstanceId:   pulumi.StringRef(oci_osmanagement_managed_instance.Test_managed_instance.Id),
//				State:               pulumi.StringRef(_var.Management_station_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagementStations(ctx *pulumi.Context, args *GetManagementStationsArgs, opts ...pulumi.InvokeOption) (*GetManagementStationsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetManagementStationsResult
	err := ctx.Invoke("oci:OsManagementHub/getManagementStations:getManagementStations", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagementStations.
type GetManagementStationsArgs struct {
	// The OCID of the compartment that contains the resources to list.
	CompartmentId *string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName *string `pulumi:"displayName"`
	// A filter to return resources that may partially match the given display name.
	DisplayNameContains *string                       `pulumi:"displayNameContains"`
	Filters             []GetManagementStationsFilter `pulumi:"filters"`
	// The OCID of the management station.
	Id *string `pulumi:"id"`
	// The OCID of the managed instance for which to list resources.
	ManagedInstanceId *string `pulumi:"managedInstanceId"`
	// The current lifecycle state for the object.
	State *string `pulumi:"state"`
}

// A collection of values returned by getManagementStations.
type GetManagementStationsResult struct {
	// The OCID of the tenancy containing the Management Station.
	CompartmentId *string `pulumi:"compartmentId"`
	// ManagementStation name
	DisplayName         *string                       `pulumi:"displayName"`
	DisplayNameContains *string                       `pulumi:"displayNameContains"`
	Filters             []GetManagementStationsFilter `pulumi:"filters"`
	// OCID for the ManagementStation config
	Id *string `pulumi:"id"`
	// OCID for the Instance associated with the Management Station.
	ManagedInstanceId *string `pulumi:"managedInstanceId"`
	// The list of management_station_collection.
	ManagementStationCollections []GetManagementStationsManagementStationCollection `pulumi:"managementStationCollections"`
	// The current state of the Management Station config.
	State *string `pulumi:"state"`
}

func GetManagementStationsOutput(ctx *pulumi.Context, args GetManagementStationsOutputArgs, opts ...pulumi.InvokeOption) GetManagementStationsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetManagementStationsResult, error) {
			args := v.(GetManagementStationsArgs)
			r, err := GetManagementStations(ctx, &args, opts...)
			var s GetManagementStationsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetManagementStationsResultOutput)
}

// A collection of arguments for invoking getManagementStations.
type GetManagementStationsOutputArgs struct {
	// The OCID of the compartment that contains the resources to list.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// A filter to return resources that may partially match the given display name.
	DisplayNameContains pulumi.StringPtrInput                 `pulumi:"displayNameContains"`
	Filters             GetManagementStationsFilterArrayInput `pulumi:"filters"`
	// The OCID of the management station.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// The OCID of the managed instance for which to list resources.
	ManagedInstanceId pulumi.StringPtrInput `pulumi:"managedInstanceId"`
	// The current lifecycle state for the object.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetManagementStationsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagementStationsArgs)(nil)).Elem()
}

// A collection of values returned by getManagementStations.
type GetManagementStationsResultOutput struct{ *pulumi.OutputState }

func (GetManagementStationsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagementStationsResult)(nil)).Elem()
}

func (o GetManagementStationsResultOutput) ToGetManagementStationsResultOutput() GetManagementStationsResultOutput {
	return o
}

func (o GetManagementStationsResultOutput) ToGetManagementStationsResultOutputWithContext(ctx context.Context) GetManagementStationsResultOutput {
	return o
}

func (o GetManagementStationsResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetManagementStationsResult] {
	return pulumix.Output[GetManagementStationsResult]{
		OutputState: o.OutputState,
	}
}

// The OCID of the tenancy containing the Management Station.
func (o GetManagementStationsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// ManagementStation name
func (o GetManagementStationsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetManagementStationsResultOutput) DisplayNameContains() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.DisplayNameContains }).(pulumi.StringPtrOutput)
}

func (o GetManagementStationsResultOutput) Filters() GetManagementStationsFilterArrayOutput {
	return o.ApplyT(func(v GetManagementStationsResult) []GetManagementStationsFilter { return v.Filters }).(GetManagementStationsFilterArrayOutput)
}

// OCID for the ManagementStation config
func (o GetManagementStationsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// OCID for the Instance associated with the Management Station.
func (o GetManagementStationsResultOutput) ManagedInstanceId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.ManagedInstanceId }).(pulumi.StringPtrOutput)
}

// The list of management_station_collection.
func (o GetManagementStationsResultOutput) ManagementStationCollections() GetManagementStationsManagementStationCollectionArrayOutput {
	return o.ApplyT(func(v GetManagementStationsResult) []GetManagementStationsManagementStationCollection {
		return v.ManagementStationCollections
	}).(GetManagementStationsManagementStationCollectionArrayOutput)
}

// The current state of the Management Station config.
func (o GetManagementStationsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagementStationsResultOutput{})
}