// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of External Asm Disk Groups in Oracle Cloud Infrastructure Database Management service.
//
// Lists ASM disk groups for the external ASM specified by `externalAsmId`.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DatabaseManagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DatabaseManagement.GetExternalAsmDiskGroups(ctx, &databasemanagement.GetExternalAsmDiskGroupsArgs{
//				ExternalAsmId: oci_database_management_external_asm.Test_external_asm.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetExternalAsmDiskGroups(ctx *pulumi.Context, args *GetExternalAsmDiskGroupsArgs, opts ...pulumi.InvokeOption) (*GetExternalAsmDiskGroupsResult, error) {
	var rv GetExternalAsmDiskGroupsResult
	err := ctx.Invoke("oci:DatabaseManagement/getExternalAsmDiskGroups:getExternalAsmDiskGroups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getExternalAsmDiskGroups.
type GetExternalAsmDiskGroupsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
	ExternalAsmId string                           `pulumi:"externalAsmId"`
	Filters       []GetExternalAsmDiskGroupsFilter `pulumi:"filters"`
}

// A collection of values returned by getExternalAsmDiskGroups.
type GetExternalAsmDiskGroupsResult struct {
	// The list of external_asm_disk_group_collection.
	ExternalAsmDiskGroupCollections []GetExternalAsmDiskGroupsExternalAsmDiskGroupCollection `pulumi:"externalAsmDiskGroupCollections"`
	ExternalAsmId                   string                                                   `pulumi:"externalAsmId"`
	Filters                         []GetExternalAsmDiskGroupsFilter                         `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetExternalAsmDiskGroupsOutput(ctx *pulumi.Context, args GetExternalAsmDiskGroupsOutputArgs, opts ...pulumi.InvokeOption) GetExternalAsmDiskGroupsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetExternalAsmDiskGroupsResult, error) {
			args := v.(GetExternalAsmDiskGroupsArgs)
			r, err := GetExternalAsmDiskGroups(ctx, &args, opts...)
			var s GetExternalAsmDiskGroupsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetExternalAsmDiskGroupsResultOutput)
}

// A collection of arguments for invoking getExternalAsmDiskGroups.
type GetExternalAsmDiskGroupsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
	ExternalAsmId pulumi.StringInput                       `pulumi:"externalAsmId"`
	Filters       GetExternalAsmDiskGroupsFilterArrayInput `pulumi:"filters"`
}

func (GetExternalAsmDiskGroupsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetExternalAsmDiskGroupsArgs)(nil)).Elem()
}

// A collection of values returned by getExternalAsmDiskGroups.
type GetExternalAsmDiskGroupsResultOutput struct{ *pulumi.OutputState }

func (GetExternalAsmDiskGroupsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetExternalAsmDiskGroupsResult)(nil)).Elem()
}

func (o GetExternalAsmDiskGroupsResultOutput) ToGetExternalAsmDiskGroupsResultOutput() GetExternalAsmDiskGroupsResultOutput {
	return o
}

func (o GetExternalAsmDiskGroupsResultOutput) ToGetExternalAsmDiskGroupsResultOutputWithContext(ctx context.Context) GetExternalAsmDiskGroupsResultOutput {
	return o
}

// The list of external_asm_disk_group_collection.
func (o GetExternalAsmDiskGroupsResultOutput) ExternalAsmDiskGroupCollections() GetExternalAsmDiskGroupsExternalAsmDiskGroupCollectionArrayOutput {
	return o.ApplyT(func(v GetExternalAsmDiskGroupsResult) []GetExternalAsmDiskGroupsExternalAsmDiskGroupCollection {
		return v.ExternalAsmDiskGroupCollections
	}).(GetExternalAsmDiskGroupsExternalAsmDiskGroupCollectionArrayOutput)
}

func (o GetExternalAsmDiskGroupsResultOutput) ExternalAsmId() pulumi.StringOutput {
	return o.ApplyT(func(v GetExternalAsmDiskGroupsResult) string { return v.ExternalAsmId }).(pulumi.StringOutput)
}

func (o GetExternalAsmDiskGroupsResultOutput) Filters() GetExternalAsmDiskGroupsFilterArrayOutput {
	return o.ApplyT(func(v GetExternalAsmDiskGroupsResult) []GetExternalAsmDiskGroupsFilter { return v.Filters }).(GetExternalAsmDiskGroupsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetExternalAsmDiskGroupsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetExternalAsmDiskGroupsResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetExternalAsmDiskGroupsResultOutput{})
}