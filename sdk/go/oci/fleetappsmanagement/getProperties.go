// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package fleetappsmanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Properties in Oracle Cloud Infrastructure Fleet Apps Management service.
//
// Returns a list of all the Properties in the specified compartment.
// The query parameter `compartmentId` is required unless the query parameter `id` is specified.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/fleetappsmanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := fleetappsmanagement.GetProperties(ctx, &fleetappsmanagement.GetPropertiesArgs{
//				CompartmentId: pulumi.StringRef(compartmentId),
//				DisplayName:   pulumi.StringRef(propertyDisplayName),
//				Id:            pulumi.StringRef(propertyId),
//				Scope:         pulumi.StringRef(propertyScope),
//				State:         pulumi.StringRef(propertyState),
//				Type:          pulumi.StringRef(propertyType),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetProperties(ctx *pulumi.Context, args *GetPropertiesArgs, opts ...pulumi.InvokeOption) (*GetPropertiesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetPropertiesResult
	err := ctx.Invoke("oci:FleetAppsManagement/getProperties:getProperties", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getProperties.
type GetPropertiesArgs struct {
	// The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string               `pulumi:"displayName"`
	Filters     []GetPropertiesFilter `pulumi:"filters"`
	// Unique identifier or OCID for listing a single Property by id. Either compartmentId or id must be provided.
	Id *string `pulumi:"id"`
	// A filter to return only resources their scope matches the given scope.
	Scope *string `pulumi:"scope"`
	// A filter to return only resources whose lifecycleState matches the given lifecycleState.
	State *string `pulumi:"state"`
	// A filter to return properties whose type matches the given type.
	Type *string `pulumi:"type"`
}

// A collection of values returned by getProperties.
type GetPropertiesResult struct {
	// Compartment OCID
	CompartmentId *string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName *string               `pulumi:"displayName"`
	Filters     []GetPropertiesFilter `pulumi:"filters"`
	// The OCID of the resource.
	Id *string `pulumi:"id"`
	// The list of property_collection.
	PropertyCollections []GetPropertiesPropertyCollection `pulumi:"propertyCollections"`
	// The scope of the property.
	Scope *string `pulumi:"scope"`
	// The current state of the Property.
	State *string `pulumi:"state"`
	// The type of the property.
	Type *string `pulumi:"type"`
}

func GetPropertiesOutput(ctx *pulumi.Context, args GetPropertiesOutputArgs, opts ...pulumi.InvokeOption) GetPropertiesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetPropertiesResultOutput, error) {
			args := v.(GetPropertiesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:FleetAppsManagement/getProperties:getProperties", args, GetPropertiesResultOutput{}, options).(GetPropertiesResultOutput), nil
		}).(GetPropertiesResultOutput)
}

// A collection of arguments for invoking getProperties.
type GetPropertiesOutputArgs struct {
	// The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput         `pulumi:"displayName"`
	Filters     GetPropertiesFilterArrayInput `pulumi:"filters"`
	// Unique identifier or OCID for listing a single Property by id. Either compartmentId or id must be provided.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return only resources their scope matches the given scope.
	Scope pulumi.StringPtrInput `pulumi:"scope"`
	// A filter to return only resources whose lifecycleState matches the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
	// A filter to return properties whose type matches the given type.
	Type pulumi.StringPtrInput `pulumi:"type"`
}

func (GetPropertiesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPropertiesArgs)(nil)).Elem()
}

// A collection of values returned by getProperties.
type GetPropertiesResultOutput struct{ *pulumi.OutputState }

func (GetPropertiesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPropertiesResult)(nil)).Elem()
}

func (o GetPropertiesResultOutput) ToGetPropertiesResultOutput() GetPropertiesResultOutput {
	return o
}

func (o GetPropertiesResultOutput) ToGetPropertiesResultOutputWithContext(ctx context.Context) GetPropertiesResultOutput {
	return o
}

// Compartment OCID
func (o GetPropertiesResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPropertiesResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
func (o GetPropertiesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPropertiesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetPropertiesResultOutput) Filters() GetPropertiesFilterArrayOutput {
	return o.ApplyT(func(v GetPropertiesResult) []GetPropertiesFilter { return v.Filters }).(GetPropertiesFilterArrayOutput)
}

// The OCID of the resource.
func (o GetPropertiesResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPropertiesResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The list of property_collection.
func (o GetPropertiesResultOutput) PropertyCollections() GetPropertiesPropertyCollectionArrayOutput {
	return o.ApplyT(func(v GetPropertiesResult) []GetPropertiesPropertyCollection { return v.PropertyCollections }).(GetPropertiesPropertyCollectionArrayOutput)
}

// The scope of the property.
func (o GetPropertiesResultOutput) Scope() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPropertiesResult) *string { return v.Scope }).(pulumi.StringPtrOutput)
}

// The current state of the Property.
func (o GetPropertiesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPropertiesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The type of the property.
func (o GetPropertiesResultOutput) Type() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPropertiesResult) *string { return v.Type }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetPropertiesResultOutput{})
}
