// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datacatalog

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Catalog Types in Oracle Cloud Infrastructure Data Catalog service.
//
// Returns a list of all types within a data catalog.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datacatalog"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datacatalog.GetCatalogTypes(ctx, &datacatalog.GetCatalogTypesArgs{
//				CatalogId:        testCatalog.Id,
//				ExternalTypeName: pulumi.StringRef(catalogTypeExternalTypeName),
//				Fields:           catalogTypeFields,
//				IsApproved:       pulumi.StringRef(catalogTypeIsApproved),
//				IsInternal:       pulumi.StringRef(catalogTypeIsInternal),
//				IsTag:            pulumi.StringRef(catalogTypeIsTag),
//				Name:             pulumi.StringRef(catalogTypeName),
//				State:            pulumi.StringRef(catalogTypeState),
//				TypeCategory:     pulumi.StringRef(catalogTypeTypeCategory),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCatalogTypes(ctx *pulumi.Context, args *GetCatalogTypesArgs, opts ...pulumi.InvokeOption) (*GetCatalogTypesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetCatalogTypesResult
	err := ctx.Invoke("oci:DataCatalog/getCatalogTypes:getCatalogTypes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCatalogTypes.
type GetCatalogTypesArgs struct {
	// Unique catalog identifier.
	CatalogId string `pulumi:"catalogId"`
	// Data type as defined in an external system.
	ExternalTypeName *string `pulumi:"externalTypeName"`
	// Specifies the fields to return in a type summary response.
	Fields  []string                `pulumi:"fields"`
	Filters []GetCatalogTypesFilter `pulumi:"filters"`
	// Indicates whether the type is approved for use as a classifying object.
	IsApproved *string `pulumi:"isApproved"`
	// Indicates whether the type is internal, making it unavailable for use by metadata elements.
	IsInternal *string `pulumi:"isInternal"`
	// Indicates whether the type can be used for tagging metadata elements.
	IsTag *string `pulumi:"isTag"`
	// Immutable resource name.
	Name *string `pulumi:"name"`
	// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
	State *string `pulumi:"state"`
	// Indicates the category of this type . For example, data assets or connections.
	TypeCategory *string `pulumi:"typeCategory"`
}

// A collection of values returned by getCatalogTypes.
type GetCatalogTypesResult struct {
	// The data catalog's OCID.
	CatalogId string `pulumi:"catalogId"`
	// Mapping type equivalence in the external system.
	ExternalTypeName *string                 `pulumi:"externalTypeName"`
	Fields           []string                `pulumi:"fields"`
	Filters          []GetCatalogTypesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Indicates whether the type is approved for use as a classifying object.
	IsApproved *string `pulumi:"isApproved"`
	// Indicates whether the type is internal, making it unavailable for use by metadata elements.
	IsInternal *string `pulumi:"isInternal"`
	// Indicates whether the type can be used for tagging metadata elements.
	IsTag *string `pulumi:"isTag"`
	// The immutable name of the type.
	Name *string `pulumi:"name"`
	// The current state of the type.
	State *string `pulumi:"state"`
	// Indicates the category this type belongs to. For instance, data assets, connections.
	TypeCategory *string `pulumi:"typeCategory"`
	// The list of type_collection.
	TypeCollections []GetCatalogTypesTypeCollection `pulumi:"typeCollections"`
}

func GetCatalogTypesOutput(ctx *pulumi.Context, args GetCatalogTypesOutputArgs, opts ...pulumi.InvokeOption) GetCatalogTypesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetCatalogTypesResultOutput, error) {
			args := v.(GetCatalogTypesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataCatalog/getCatalogTypes:getCatalogTypes", args, GetCatalogTypesResultOutput{}, options).(GetCatalogTypesResultOutput), nil
		}).(GetCatalogTypesResultOutput)
}

// A collection of arguments for invoking getCatalogTypes.
type GetCatalogTypesOutputArgs struct {
	// Unique catalog identifier.
	CatalogId pulumi.StringInput `pulumi:"catalogId"`
	// Data type as defined in an external system.
	ExternalTypeName pulumi.StringPtrInput `pulumi:"externalTypeName"`
	// Specifies the fields to return in a type summary response.
	Fields  pulumi.StringArrayInput         `pulumi:"fields"`
	Filters GetCatalogTypesFilterArrayInput `pulumi:"filters"`
	// Indicates whether the type is approved for use as a classifying object.
	IsApproved pulumi.StringPtrInput `pulumi:"isApproved"`
	// Indicates whether the type is internal, making it unavailable for use by metadata elements.
	IsInternal pulumi.StringPtrInput `pulumi:"isInternal"`
	// Indicates whether the type can be used for tagging metadata elements.
	IsTag pulumi.StringPtrInput `pulumi:"isTag"`
	// Immutable resource name.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
	// Indicates the category of this type . For example, data assets or connections.
	TypeCategory pulumi.StringPtrInput `pulumi:"typeCategory"`
}

func (GetCatalogTypesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCatalogTypesArgs)(nil)).Elem()
}

// A collection of values returned by getCatalogTypes.
type GetCatalogTypesResultOutput struct{ *pulumi.OutputState }

func (GetCatalogTypesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCatalogTypesResult)(nil)).Elem()
}

func (o GetCatalogTypesResultOutput) ToGetCatalogTypesResultOutput() GetCatalogTypesResultOutput {
	return o
}

func (o GetCatalogTypesResultOutput) ToGetCatalogTypesResultOutputWithContext(ctx context.Context) GetCatalogTypesResultOutput {
	return o
}

// The data catalog's OCID.
func (o GetCatalogTypesResultOutput) CatalogId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) string { return v.CatalogId }).(pulumi.StringOutput)
}

// Mapping type equivalence in the external system.
func (o GetCatalogTypesResultOutput) ExternalTypeName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) *string { return v.ExternalTypeName }).(pulumi.StringPtrOutput)
}

func (o GetCatalogTypesResultOutput) Fields() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) []string { return v.Fields }).(pulumi.StringArrayOutput)
}

func (o GetCatalogTypesResultOutput) Filters() GetCatalogTypesFilterArrayOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) []GetCatalogTypesFilter { return v.Filters }).(GetCatalogTypesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCatalogTypesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) string { return v.Id }).(pulumi.StringOutput)
}

// Indicates whether the type is approved for use as a classifying object.
func (o GetCatalogTypesResultOutput) IsApproved() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) *string { return v.IsApproved }).(pulumi.StringPtrOutput)
}

// Indicates whether the type is internal, making it unavailable for use by metadata elements.
func (o GetCatalogTypesResultOutput) IsInternal() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) *string { return v.IsInternal }).(pulumi.StringPtrOutput)
}

// Indicates whether the type can be used for tagging metadata elements.
func (o GetCatalogTypesResultOutput) IsTag() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) *string { return v.IsTag }).(pulumi.StringPtrOutput)
}

// The immutable name of the type.
func (o GetCatalogTypesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The current state of the type.
func (o GetCatalogTypesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// Indicates the category this type belongs to. For instance, data assets, connections.
func (o GetCatalogTypesResultOutput) TypeCategory() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) *string { return v.TypeCategory }).(pulumi.StringPtrOutput)
}

// The list of type_collection.
func (o GetCatalogTypesResultOutput) TypeCollections() GetCatalogTypesTypeCollectionArrayOutput {
	return o.ApplyT(func(v GetCatalogTypesResult) []GetCatalogTypesTypeCollection { return v.TypeCollections }).(GetCatalogTypesTypeCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCatalogTypesResultOutput{})
}
