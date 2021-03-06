// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Backups in Oracle Cloud Infrastructure Database service.
//
// Gets a list of backups based on the `databaseId` or `compartmentId` specified. Either one of these query parameters must be provided.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/Database"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := Database.GetBackups(ctx, &database.GetBackupsArgs{
// 			CompartmentId: pulumi.StringRef(_var.Compartment_id),
// 			DatabaseId:    pulumi.StringRef(oci_database_database.Test_database.Id),
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetBackups(ctx *pulumi.Context, args *GetBackupsArgs, opts ...pulumi.InvokeOption) (*GetBackupsResult, error) {
	var rv GetBackupsResult
	err := ctx.Invoke("oci:Database/getBackups:getBackups", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getBackups.
type GetBackupsArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId *string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
	DatabaseId *string            `pulumi:"databaseId"`
	Filters    []GetBackupsFilter `pulumi:"filters"`
}

// A collection of values returned by getBackups.
type GetBackupsResult struct {
	// The list of backups.
	Backups []GetBackupsBackup `pulumi:"backups"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
	DatabaseId *string            `pulumi:"databaseId"`
	Filters    []GetBackupsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetBackupsOutput(ctx *pulumi.Context, args GetBackupsOutputArgs, opts ...pulumi.InvokeOption) GetBackupsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetBackupsResult, error) {
			args := v.(GetBackupsArgs)
			r, err := GetBackups(ctx, &args, opts...)
			var s GetBackupsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetBackupsResultOutput)
}

// A collection of arguments for invoking getBackups.
type GetBackupsOutputArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
	DatabaseId pulumi.StringPtrInput      `pulumi:"databaseId"`
	Filters    GetBackupsFilterArrayInput `pulumi:"filters"`
}

func (GetBackupsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetBackupsArgs)(nil)).Elem()
}

// A collection of values returned by getBackups.
type GetBackupsResultOutput struct{ *pulumi.OutputState }

func (GetBackupsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetBackupsResult)(nil)).Elem()
}

func (o GetBackupsResultOutput) ToGetBackupsResultOutput() GetBackupsResultOutput {
	return o
}

func (o GetBackupsResultOutput) ToGetBackupsResultOutputWithContext(ctx context.Context) GetBackupsResultOutput {
	return o
}

// The list of backups.
func (o GetBackupsResultOutput) Backups() GetBackupsBackupArrayOutput {
	return o.ApplyT(func(v GetBackupsResult) []GetBackupsBackup { return v.Backups }).(GetBackupsBackupArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetBackupsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetBackupsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
func (o GetBackupsResultOutput) DatabaseId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetBackupsResult) *string { return v.DatabaseId }).(pulumi.StringPtrOutput)
}

func (o GetBackupsResultOutput) Filters() GetBackupsFilterArrayOutput {
	return o.ApplyT(func(v GetBackupsResult) []GetBackupsFilter { return v.Filters }).(GetBackupsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetBackupsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetBackupsResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetBackupsResultOutput{})
}
