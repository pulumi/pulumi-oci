// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Managed Database Group resource in Oracle Cloud Infrastructure Database Management service.
//
// Gets the details for the Managed Database Group specified by managedDatabaseGroupId.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/databasemanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := databasemanagement.GetManagedDatabaseGroup(ctx, &databasemanagement.GetManagedDatabaseGroupArgs{
//				ManagedDatabaseGroupId: testManagedDatabaseGroupOciDatabaseManagementManagedDatabaseGroup.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupManagedDatabaseGroup(ctx *pulumi.Context, args *LookupManagedDatabaseGroupArgs, opts ...pulumi.InvokeOption) (*LookupManagedDatabaseGroupResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupManagedDatabaseGroupResult
	err := ctx.Invoke("oci:DatabaseManagement/getManagedDatabaseGroup:getManagedDatabaseGroup", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedDatabaseGroup.
type LookupManagedDatabaseGroupArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
	ManagedDatabaseGroupId string `pulumi:"managedDatabaseGroupId"`
}

// A collection of values returned by getManagedDatabaseGroup.
type LookupManagedDatabaseGroupResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database resides.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The information specified by the user about the Managed Database Group.
	Description string `pulumi:"description"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	Id                     string `pulumi:"id"`
	ManagedDatabaseGroupId string `pulumi:"managedDatabaseGroupId"`
	// A list of Managed Databases in the Managed Database Group.
	ManagedDatabases []GetManagedDatabaseGroupManagedDatabase `pulumi:"managedDatabases"`
	// The name of the Managed Database Group.
	Name string `pulumi:"name"`
	// The current lifecycle state of the Managed Database Group.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the Managed Database Group was created.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the Managed Database Group was last updated.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupManagedDatabaseGroupOutput(ctx *pulumi.Context, args LookupManagedDatabaseGroupOutputArgs, opts ...pulumi.InvokeOption) LookupManagedDatabaseGroupResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupManagedDatabaseGroupResultOutput, error) {
			args := v.(LookupManagedDatabaseGroupArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DatabaseManagement/getManagedDatabaseGroup:getManagedDatabaseGroup", args, LookupManagedDatabaseGroupResultOutput{}, options).(LookupManagedDatabaseGroupResultOutput), nil
		}).(LookupManagedDatabaseGroupResultOutput)
}

// A collection of arguments for invoking getManagedDatabaseGroup.
type LookupManagedDatabaseGroupOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
	ManagedDatabaseGroupId pulumi.StringInput `pulumi:"managedDatabaseGroupId"`
}

func (LookupManagedDatabaseGroupOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagedDatabaseGroupArgs)(nil)).Elem()
}

// A collection of values returned by getManagedDatabaseGroup.
type LookupManagedDatabaseGroupResultOutput struct{ *pulumi.OutputState }

func (LookupManagedDatabaseGroupResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupManagedDatabaseGroupResult)(nil)).Elem()
}

func (o LookupManagedDatabaseGroupResultOutput) ToLookupManagedDatabaseGroupResultOutput() LookupManagedDatabaseGroupResultOutput {
	return o
}

func (o LookupManagedDatabaseGroupResultOutput) ToLookupManagedDatabaseGroupResultOutputWithContext(ctx context.Context) LookupManagedDatabaseGroupResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database resides.
func (o LookupManagedDatabaseGroupResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupManagedDatabaseGroupResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The information specified by the user about the Managed Database Group.
func (o LookupManagedDatabaseGroupResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) string { return v.Description }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupManagedDatabaseGroupResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
func (o LookupManagedDatabaseGroupResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupManagedDatabaseGroupResultOutput) ManagedDatabaseGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) string { return v.ManagedDatabaseGroupId }).(pulumi.StringOutput)
}

// A list of Managed Databases in the Managed Database Group.
func (o LookupManagedDatabaseGroupResultOutput) ManagedDatabases() GetManagedDatabaseGroupManagedDatabaseArrayOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) []GetManagedDatabaseGroupManagedDatabase {
		return v.ManagedDatabases
	}).(GetManagedDatabaseGroupManagedDatabaseArrayOutput)
}

// The name of the Managed Database Group.
func (o LookupManagedDatabaseGroupResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) string { return v.Name }).(pulumi.StringOutput)
}

// The current lifecycle state of the Managed Database Group.
func (o LookupManagedDatabaseGroupResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupManagedDatabaseGroupResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the Managed Database Group was created.
func (o LookupManagedDatabaseGroupResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the Managed Database Group was last updated.
func (o LookupManagedDatabaseGroupResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupManagedDatabaseGroupResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupManagedDatabaseGroupResultOutput{})
}
