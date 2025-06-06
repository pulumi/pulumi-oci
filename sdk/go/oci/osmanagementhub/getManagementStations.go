// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagementhub

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Management Stations in Oracle Cloud Infrastructure Os Management Hub service.
//
// Lists management stations within the specified compartment. Filter the list against a variety of criteria
// including but not limited to name, status, and location.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/osmanagementhub"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := osmanagementhub.GetManagementStations(ctx, &osmanagementhub.GetManagementStationsArgs{
//				CompartmentId:       pulumi.StringRef(compartmentId),
//				DisplayName:         pulumi.StringRef(managementStationDisplayName),
//				DisplayNameContains: pulumi.StringRef(managementStationDisplayNameContains),
//				Id:                  pulumi.StringRef(managementStationId),
//				Locations:           managementStationLocation,
//				LocationNotEqualTos: managementStationLocationNotEqualTo,
//				ManagedInstanceId:   pulumi.StringRef(testManagedInstance.Id),
//				State:               pulumi.StringRef(managementStationState),
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
	// (Updatable) The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return resources that match the given user-friendly name.
	DisplayName *string `pulumi:"displayName"`
	// A filter to return resources that may partially match the given display name.
	DisplayNameContains *string                       `pulumi:"displayNameContains"`
	Filters             []GetManagementStationsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station. A filter that returns information about the specified management station.
	Id *string `pulumi:"id"`
	// A filter to return only resources whose location does not match the given value.
	LocationNotEqualTos []string `pulumi:"locationNotEqualTos"`
	// A filter to return only resources whose location matches the given value.
	Locations []string `pulumi:"locations"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance. This filter returns resources associated with this managed instance.
	ManagedInstanceId *string `pulumi:"managedInstanceId"`
	// A filter that returns information for management stations in the specified state.
	State *string `pulumi:"state"`
}

// A collection of values returned by getManagementStations.
type GetManagementStationsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the management station.
	CompartmentId *string `pulumi:"compartmentId"`
	// User-friendly name for the management station.
	DisplayName         *string                       `pulumi:"displayName"`
	DisplayNameContains *string                       `pulumi:"displayNameContains"`
	Filters             []GetManagementStationsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
	Id                  *string  `pulumi:"id"`
	LocationNotEqualTos []string `pulumi:"locationNotEqualTos"`
	// The location of the instance that is acting as the management station.
	Locations []string `pulumi:"locations"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance that is acting as the management station.
	ManagedInstanceId *string `pulumi:"managedInstanceId"`
	// The list of management_station_collection.
	ManagementStationCollections []GetManagementStationsManagementStationCollection `pulumi:"managementStationCollections"`
	// The current state of the management station.
	State *string `pulumi:"state"`
}

func GetManagementStationsOutput(ctx *pulumi.Context, args GetManagementStationsOutputArgs, opts ...pulumi.InvokeOption) GetManagementStationsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetManagementStationsResultOutput, error) {
			args := v.(GetManagementStationsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:OsManagementHub/getManagementStations:getManagementStations", args, GetManagementStationsResultOutput{}, options).(GetManagementStationsResultOutput), nil
		}).(GetManagementStationsResultOutput)
}

// A collection of arguments for invoking getManagementStations.
type GetManagementStationsOutputArgs struct {
	// (Updatable) The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return resources that match the given user-friendly name.
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// A filter to return resources that may partially match the given display name.
	DisplayNameContains pulumi.StringPtrInput                 `pulumi:"displayNameContains"`
	Filters             GetManagementStationsFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station. A filter that returns information about the specified management station.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return only resources whose location does not match the given value.
	LocationNotEqualTos pulumi.StringArrayInput `pulumi:"locationNotEqualTos"`
	// A filter to return only resources whose location matches the given value.
	Locations pulumi.StringArrayInput `pulumi:"locations"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance. This filter returns resources associated with this managed instance.
	ManagedInstanceId pulumi.StringPtrInput `pulumi:"managedInstanceId"`
	// A filter that returns information for management stations in the specified state.
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

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the management station.
func (o GetManagementStationsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// User-friendly name for the management station.
func (o GetManagementStationsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetManagementStationsResultOutput) DisplayNameContains() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.DisplayNameContains }).(pulumi.StringPtrOutput)
}

func (o GetManagementStationsResultOutput) Filters() GetManagementStationsFilterArrayOutput {
	return o.ApplyT(func(v GetManagementStationsResult) []GetManagementStationsFilter { return v.Filters }).(GetManagementStationsFilterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
func (o GetManagementStationsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

func (o GetManagementStationsResultOutput) LocationNotEqualTos() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetManagementStationsResult) []string { return v.LocationNotEqualTos }).(pulumi.StringArrayOutput)
}

// The location of the instance that is acting as the management station.
func (o GetManagementStationsResultOutput) Locations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetManagementStationsResult) []string { return v.Locations }).(pulumi.StringArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance that is acting as the management station.
func (o GetManagementStationsResultOutput) ManagedInstanceId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.ManagedInstanceId }).(pulumi.StringPtrOutput)
}

// The list of management_station_collection.
func (o GetManagementStationsResultOutput) ManagementStationCollections() GetManagementStationsManagementStationCollectionArrayOutput {
	return o.ApplyT(func(v GetManagementStationsResult) []GetManagementStationsManagementStationCollection {
		return v.ManagementStationCollections
	}).(GetManagementStationsManagementStationCollectionArrayOutput)
}

// The current state of the management station.
func (o GetManagementStationsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementStationsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagementStationsResultOutput{})
}
