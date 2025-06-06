// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package servicecatalog

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Service Catalog Association resource in Oracle Cloud Infrastructure Service Catalog service.
//
// Gets detailed information about specific service catalog association.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/servicecatalog"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := servicecatalog.GetServiceCatalogAssociation(ctx, &servicecatalog.GetServiceCatalogAssociationArgs{
//				ServiceCatalogAssociationId: testServiceCatalogAssociationOciServiceCatalogServiceCatalogAssociation.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetServiceCatalogAssociation(ctx *pulumi.Context, args *GetServiceCatalogAssociationArgs, opts ...pulumi.InvokeOption) (*GetServiceCatalogAssociationResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetServiceCatalogAssociationResult
	err := ctx.Invoke("oci:ServiceCatalog/getServiceCatalogAssociation:getServiceCatalogAssociation", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getServiceCatalogAssociation.
type GetServiceCatalogAssociationArgs struct {
	// The unique identifier of the service catalog association.
	ServiceCatalogAssociationId string `pulumi:"serviceCatalogAssociationId"`
}

// A collection of values returned by getServiceCatalogAssociation.
type GetServiceCatalogAssociationResult struct {
	// Identifier of the entity being associated with service catalog.
	EntityId string `pulumi:"entityId"`
	// The type of the entity that is associated with the service catalog.
	EntityType string `pulumi:"entityType"`
	// Identifier of the association.
	Id                          string `pulumi:"id"`
	ServiceCatalogAssociationId string `pulumi:"serviceCatalogAssociationId"`
	// Identifier of the service catalog.
	ServiceCatalogId string `pulumi:"serviceCatalogId"`
	// Timestamp of when the resource was associated with service catalog.
	TimeCreated string `pulumi:"timeCreated"`
}

func GetServiceCatalogAssociationOutput(ctx *pulumi.Context, args GetServiceCatalogAssociationOutputArgs, opts ...pulumi.InvokeOption) GetServiceCatalogAssociationResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetServiceCatalogAssociationResultOutput, error) {
			args := v.(GetServiceCatalogAssociationArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ServiceCatalog/getServiceCatalogAssociation:getServiceCatalogAssociation", args, GetServiceCatalogAssociationResultOutput{}, options).(GetServiceCatalogAssociationResultOutput), nil
		}).(GetServiceCatalogAssociationResultOutput)
}

// A collection of arguments for invoking getServiceCatalogAssociation.
type GetServiceCatalogAssociationOutputArgs struct {
	// The unique identifier of the service catalog association.
	ServiceCatalogAssociationId pulumi.StringInput `pulumi:"serviceCatalogAssociationId"`
}

func (GetServiceCatalogAssociationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetServiceCatalogAssociationArgs)(nil)).Elem()
}

// A collection of values returned by getServiceCatalogAssociation.
type GetServiceCatalogAssociationResultOutput struct{ *pulumi.OutputState }

func (GetServiceCatalogAssociationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetServiceCatalogAssociationResult)(nil)).Elem()
}

func (o GetServiceCatalogAssociationResultOutput) ToGetServiceCatalogAssociationResultOutput() GetServiceCatalogAssociationResultOutput {
	return o
}

func (o GetServiceCatalogAssociationResultOutput) ToGetServiceCatalogAssociationResultOutputWithContext(ctx context.Context) GetServiceCatalogAssociationResultOutput {
	return o
}

// Identifier of the entity being associated with service catalog.
func (o GetServiceCatalogAssociationResultOutput) EntityId() pulumi.StringOutput {
	return o.ApplyT(func(v GetServiceCatalogAssociationResult) string { return v.EntityId }).(pulumi.StringOutput)
}

// The type of the entity that is associated with the service catalog.
func (o GetServiceCatalogAssociationResultOutput) EntityType() pulumi.StringOutput {
	return o.ApplyT(func(v GetServiceCatalogAssociationResult) string { return v.EntityType }).(pulumi.StringOutput)
}

// Identifier of the association.
func (o GetServiceCatalogAssociationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetServiceCatalogAssociationResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetServiceCatalogAssociationResultOutput) ServiceCatalogAssociationId() pulumi.StringOutput {
	return o.ApplyT(func(v GetServiceCatalogAssociationResult) string { return v.ServiceCatalogAssociationId }).(pulumi.StringOutput)
}

// Identifier of the service catalog.
func (o GetServiceCatalogAssociationResultOutput) ServiceCatalogId() pulumi.StringOutput {
	return o.ApplyT(func(v GetServiceCatalogAssociationResult) string { return v.ServiceCatalogId }).(pulumi.StringOutput)
}

// Timestamp of when the resource was associated with service catalog.
func (o GetServiceCatalogAssociationResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetServiceCatalogAssociationResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetServiceCatalogAssociationResultOutput{})
}
