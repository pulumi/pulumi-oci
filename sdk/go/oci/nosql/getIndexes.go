// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package nosql

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Indexes in Oracle Cloud Infrastructure NoSQL Database service.
//
// Get a list of indexes on a table.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Nosql"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Nosql.GetIndexes(ctx, &nosql.GetIndexesArgs{
//				TableNameOrId: oci_nosql_table_name_or.Test_table_name_or.Id,
//				CompartmentId: pulumi.StringRef(_var.Compartment_id),
//				Name:          pulumi.StringRef(_var.Index_name),
//				State:         pulumi.StringRef(_var.Index_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetIndexes(ctx *pulumi.Context, args *GetIndexesArgs, opts ...pulumi.InvokeOption) (*GetIndexesResult, error) {
	var rv GetIndexesResult
	err := ctx.Invoke("oci:Nosql/getIndexes:getIndexes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getIndexes.
type GetIndexesArgs struct {
	// The ID of a table's compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
	CompartmentId *string            `pulumi:"compartmentId"`
	Filters       []GetIndexesFilter `pulumi:"filters"`
	// A shell-globbing-style (*?[]) filter for names.
	Name *string `pulumi:"name"`
	// Filter list by the lifecycle state of the item.
	State *string `pulumi:"state"`
	// A table name within the compartment, or a table OCID.
	TableNameOrId string `pulumi:"tableNameOrId"`
}

// A collection of values returned by getIndexes.
type GetIndexesResult struct {
	// Compartment Identifier.
	CompartmentId *string            `pulumi:"compartmentId"`
	Filters       []GetIndexesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of index_collection.
	IndexCollections []GetIndexesIndexCollection `pulumi:"indexCollections"`
	// Index name.
	Name *string `pulumi:"name"`
	// The state of an index.
	State         *string `pulumi:"state"`
	TableNameOrId string  `pulumi:"tableNameOrId"`
}

func GetIndexesOutput(ctx *pulumi.Context, args GetIndexesOutputArgs, opts ...pulumi.InvokeOption) GetIndexesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetIndexesResult, error) {
			args := v.(GetIndexesArgs)
			r, err := GetIndexes(ctx, &args, opts...)
			var s GetIndexesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetIndexesResultOutput)
}

// A collection of arguments for invoking getIndexes.
type GetIndexesOutputArgs struct {
	// The ID of a table's compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
	CompartmentId pulumi.StringPtrInput      `pulumi:"compartmentId"`
	Filters       GetIndexesFilterArrayInput `pulumi:"filters"`
	// A shell-globbing-style (*?[]) filter for names.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// Filter list by the lifecycle state of the item.
	State pulumi.StringPtrInput `pulumi:"state"`
	// A table name within the compartment, or a table OCID.
	TableNameOrId pulumi.StringInput `pulumi:"tableNameOrId"`
}

func (GetIndexesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetIndexesArgs)(nil)).Elem()
}

// A collection of values returned by getIndexes.
type GetIndexesResultOutput struct{ *pulumi.OutputState }

func (GetIndexesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetIndexesResult)(nil)).Elem()
}

func (o GetIndexesResultOutput) ToGetIndexesResultOutput() GetIndexesResultOutput {
	return o
}

func (o GetIndexesResultOutput) ToGetIndexesResultOutputWithContext(ctx context.Context) GetIndexesResultOutput {
	return o
}

// Compartment Identifier.
func (o GetIndexesResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetIndexesResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

func (o GetIndexesResultOutput) Filters() GetIndexesFilterArrayOutput {
	return o.ApplyT(func(v GetIndexesResult) []GetIndexesFilter { return v.Filters }).(GetIndexesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetIndexesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetIndexesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of index_collection.
func (o GetIndexesResultOutput) IndexCollections() GetIndexesIndexCollectionArrayOutput {
	return o.ApplyT(func(v GetIndexesResult) []GetIndexesIndexCollection { return v.IndexCollections }).(GetIndexesIndexCollectionArrayOutput)
}

// Index name.
func (o GetIndexesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetIndexesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The state of an index.
func (o GetIndexesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetIndexesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func (o GetIndexesResultOutput) TableNameOrId() pulumi.StringOutput {
	return o.ApplyT(func(v GetIndexesResult) string { return v.TableNameOrId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetIndexesResultOutput{})
}