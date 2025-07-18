// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package bigdataservice

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Bds Instance Node Backup resource in Oracle Cloud Infrastructure Big Data Service service.
//
// Returns details of NodeBackup identified by the given ID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/bigdataservice"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := bigdataservice.GetBdsInstanceNodeBackup(ctx, &bigdataservice.GetBdsInstanceNodeBackupArgs{
//				BdsInstanceId: testBdsInstance.Id,
//				NodeBackupId:  testBackup.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupBdsInstanceNodeBackup(ctx *pulumi.Context, args *LookupBdsInstanceNodeBackupArgs, opts ...pulumi.InvokeOption) (*LookupBdsInstanceNodeBackupResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupBdsInstanceNodeBackupResult
	err := ctx.Invoke("oci:BigDataService/getBdsInstanceNodeBackup:getBdsInstanceNodeBackup", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getBdsInstanceNodeBackup.
type LookupBdsInstanceNodeBackupArgs struct {
	// The OCID of the cluster.
	BdsInstanceId string `pulumi:"bdsInstanceId"`
	// Unique assigned identifier of the nodeBackupId.
	NodeBackupId string `pulumi:"nodeBackupId"`
}

// A collection of values returned by getBdsInstanceNodeBackup.
type LookupBdsInstanceNodeBackupResult struct {
	// type based on how backup action was initiated.
	BackupTriggerType string `pulumi:"backupTriggerType"`
	// Incremental backup type includes only the changes since the last backup. Full backup type includes all changes since the volume was created.
	BackupType    string `pulumi:"backupType"`
	BdsInstanceId string `pulumi:"bdsInstanceId"`
	// BDS generated name for the backup. Format is nodeHostName_timeCreated.
	DisplayName string `pulumi:"displayName"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The ID of the nodeBackupConfiguration if the NodeBackup is automatically created by applying the configuration.
	NodeBackupConfigId string `pulumi:"nodeBackupConfigId"`
	NodeBackupId       string `pulumi:"nodeBackupId"`
	// Host name of the node to which this backup belongs.
	NodeHostName string `pulumi:"nodeHostName"`
	// The instance OCID of the node, which is the resource from which the node backup was acquired.
	NodeInstanceId string `pulumi:"nodeInstanceId"`
	// The state of the NodeBackup.
	State string `pulumi:"state"`
	// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
}

func LookupBdsInstanceNodeBackupOutput(ctx *pulumi.Context, args LookupBdsInstanceNodeBackupOutputArgs, opts ...pulumi.InvokeOption) LookupBdsInstanceNodeBackupResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupBdsInstanceNodeBackupResultOutput, error) {
			args := v.(LookupBdsInstanceNodeBackupArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:BigDataService/getBdsInstanceNodeBackup:getBdsInstanceNodeBackup", args, LookupBdsInstanceNodeBackupResultOutput{}, options).(LookupBdsInstanceNodeBackupResultOutput), nil
		}).(LookupBdsInstanceNodeBackupResultOutput)
}

// A collection of arguments for invoking getBdsInstanceNodeBackup.
type LookupBdsInstanceNodeBackupOutputArgs struct {
	// The OCID of the cluster.
	BdsInstanceId pulumi.StringInput `pulumi:"bdsInstanceId"`
	// Unique assigned identifier of the nodeBackupId.
	NodeBackupId pulumi.StringInput `pulumi:"nodeBackupId"`
}

func (LookupBdsInstanceNodeBackupOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupBdsInstanceNodeBackupArgs)(nil)).Elem()
}

// A collection of values returned by getBdsInstanceNodeBackup.
type LookupBdsInstanceNodeBackupResultOutput struct{ *pulumi.OutputState }

func (LookupBdsInstanceNodeBackupResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupBdsInstanceNodeBackupResult)(nil)).Elem()
}

func (o LookupBdsInstanceNodeBackupResultOutput) ToLookupBdsInstanceNodeBackupResultOutput() LookupBdsInstanceNodeBackupResultOutput {
	return o
}

func (o LookupBdsInstanceNodeBackupResultOutput) ToLookupBdsInstanceNodeBackupResultOutputWithContext(ctx context.Context) LookupBdsInstanceNodeBackupResultOutput {
	return o
}

// type based on how backup action was initiated.
func (o LookupBdsInstanceNodeBackupResultOutput) BackupTriggerType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBdsInstanceNodeBackupResult) string { return v.BackupTriggerType }).(pulumi.StringOutput)
}

// Incremental backup type includes only the changes since the last backup. Full backup type includes all changes since the volume was created.
func (o LookupBdsInstanceNodeBackupResultOutput) BackupType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBdsInstanceNodeBackupResult) string { return v.BackupType }).(pulumi.StringOutput)
}

func (o LookupBdsInstanceNodeBackupResultOutput) BdsInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBdsInstanceNodeBackupResult) string { return v.BdsInstanceId }).(pulumi.StringOutput)
}

// BDS generated name for the backup. Format is nodeHostName_timeCreated.
func (o LookupBdsInstanceNodeBackupResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBdsInstanceNodeBackupResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o LookupBdsInstanceNodeBackupResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBdsInstanceNodeBackupResult) string { return v.Id }).(pulumi.StringOutput)
}

// The ID of the nodeBackupConfiguration if the NodeBackup is automatically created by applying the configuration.
func (o LookupBdsInstanceNodeBackupResultOutput) NodeBackupConfigId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBdsInstanceNodeBackupResult) string { return v.NodeBackupConfigId }).(pulumi.StringOutput)
}

func (o LookupBdsInstanceNodeBackupResultOutput) NodeBackupId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBdsInstanceNodeBackupResult) string { return v.NodeBackupId }).(pulumi.StringOutput)
}

// Host name of the node to which this backup belongs.
func (o LookupBdsInstanceNodeBackupResultOutput) NodeHostName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBdsInstanceNodeBackupResult) string { return v.NodeHostName }).(pulumi.StringOutput)
}

// The instance OCID of the node, which is the resource from which the node backup was acquired.
func (o LookupBdsInstanceNodeBackupResultOutput) NodeInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBdsInstanceNodeBackupResult) string { return v.NodeInstanceId }).(pulumi.StringOutput)
}

// The state of the NodeBackup.
func (o LookupBdsInstanceNodeBackupResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBdsInstanceNodeBackupResult) string { return v.State }).(pulumi.StringOutput)
}

// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
func (o LookupBdsInstanceNodeBackupResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBdsInstanceNodeBackupResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupBdsInstanceNodeBackupResultOutput{})
}
