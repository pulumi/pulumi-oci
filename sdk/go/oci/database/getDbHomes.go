// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Db Homes in Oracle Cloud Infrastructure Database service.
//
// Lists the Database Homes in the specified DB system and compartment. A Database Home is a directory where Oracle Database software is installed.
func GetDbHomes(ctx *pulumi.Context, args *GetDbHomesArgs, opts ...pulumi.InvokeOption) (*GetDbHomesResult, error) {
	var rv GetDbHomesResult
	err := ctx.Invoke("oci:Database/getDbHomes:getDbHomes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDbHomes.
type GetDbHomesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup. Specify a backupId to list only the DB systems or DB homes that support creating a database using this backup in this compartment.
	BackupId *string `pulumi:"backupId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). If provided, filters the results to the set of database versions which are supported for the DB system.
	DbSystemId *string `pulumi:"dbSystemId"`
	// A filter to return only DB Homes that match the specified dbVersion.
	DbVersion *string `pulumi:"dbVersion"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string            `pulumi:"displayName"`
	Filters     []GetDbHomesFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
	VmClusterId *string `pulumi:"vmClusterId"`
}

// A collection of values returned by getDbHomes.
type GetDbHomesResult struct {
	BackupId *string `pulumi:"backupId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of db_homes.
	DbHomes []GetDbHomesDbHome `pulumi:"dbHomes"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
	DbSystemId *string `pulumi:"dbSystemId"`
	// The Oracle Database version.
	DbVersion *string `pulumi:"dbVersion"`
	// The user-provided name for the Database Home. The name does not need to be unique.
	DisplayName *string            `pulumi:"displayName"`
	Filters     []GetDbHomesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the Database Home.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
	VmClusterId *string `pulumi:"vmClusterId"`
}

func GetDbHomesOutput(ctx *pulumi.Context, args GetDbHomesOutputArgs, opts ...pulumi.InvokeOption) GetDbHomesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDbHomesResult, error) {
			args := v.(GetDbHomesArgs)
			r, err := GetDbHomes(ctx, &args, opts...)
			var s GetDbHomesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDbHomesResultOutput)
}

// A collection of arguments for invoking getDbHomes.
type GetDbHomesOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup. Specify a backupId to list only the DB systems or DB homes that support creating a database using this backup in this compartment.
	BackupId pulumi.StringPtrInput `pulumi:"backupId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). If provided, filters the results to the set of database versions which are supported for the DB system.
	DbSystemId pulumi.StringPtrInput `pulumi:"dbSystemId"`
	// A filter to return only DB Homes that match the specified dbVersion.
	DbVersion pulumi.StringPtrInput `pulumi:"dbVersion"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName pulumi.StringPtrInput      `pulumi:"displayName"`
	Filters     GetDbHomesFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State pulumi.StringPtrInput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
	VmClusterId pulumi.StringPtrInput `pulumi:"vmClusterId"`
}

func (GetDbHomesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbHomesArgs)(nil)).Elem()
}

// A collection of values returned by getDbHomes.
type GetDbHomesResultOutput struct{ *pulumi.OutputState }

func (GetDbHomesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbHomesResult)(nil)).Elem()
}

func (o GetDbHomesResultOutput) ToGetDbHomesResultOutput() GetDbHomesResultOutput {
	return o
}

func (o GetDbHomesResultOutput) ToGetDbHomesResultOutputWithContext(ctx context.Context) GetDbHomesResultOutput {
	return o
}

func (o GetDbHomesResultOutput) BackupId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDbHomesResult) *string { return v.BackupId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetDbHomesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbHomesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of db_homes.
func (o GetDbHomesResultOutput) DbHomes() GetDbHomesDbHomeArrayOutput {
	return o.ApplyT(func(v GetDbHomesResult) []GetDbHomesDbHome { return v.DbHomes }).(GetDbHomesDbHomeArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
func (o GetDbHomesResultOutput) DbSystemId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDbHomesResult) *string { return v.DbSystemId }).(pulumi.StringPtrOutput)
}

// The Oracle Database version.
func (o GetDbHomesResultOutput) DbVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDbHomesResult) *string { return v.DbVersion }).(pulumi.StringPtrOutput)
}

// The user-provided name for the Database Home. The name does not need to be unique.
func (o GetDbHomesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDbHomesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetDbHomesResultOutput) Filters() GetDbHomesFilterArrayOutput {
	return o.ApplyT(func(v GetDbHomesResult) []GetDbHomesFilter { return v.Filters }).(GetDbHomesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDbHomesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbHomesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the Database Home.
func (o GetDbHomesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDbHomesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
func (o GetDbHomesResultOutput) VmClusterId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDbHomesResult) *string { return v.VmClusterId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDbHomesResultOutput{})
}