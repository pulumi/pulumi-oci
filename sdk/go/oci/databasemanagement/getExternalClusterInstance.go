// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific External Cluster Instance resource in Oracle Cloud Infrastructure Database Management service.
//
// Gets the details for the external cluster instance specified by `externalClusterInstanceId`.
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
//			_, err := DatabaseManagement.GetExternalClusterInstance(ctx, &databasemanagement.GetExternalClusterInstanceArgs{
//				ExternalClusterInstanceId: oci_database_management_external_cluster_instance.Test_external_cluster_instance.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupExternalClusterInstance(ctx *pulumi.Context, args *LookupExternalClusterInstanceArgs, opts ...pulumi.InvokeOption) (*LookupExternalClusterInstanceResult, error) {
	var rv LookupExternalClusterInstanceResult
	err := ctx.Invoke("oci:DatabaseManagement/getExternalClusterInstance:getExternalClusterInstance", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getExternalClusterInstance.
type LookupExternalClusterInstanceArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster instance.
	ExternalClusterInstanceId string `pulumi:"externalClusterInstanceId"`
}

// A collection of values returned by getExternalClusterInstance.
type LookupExternalClusterInstanceResult struct {
	// The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
	AdrHomeDirectory string `pulumi:"adrHomeDirectory"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The name of the external cluster instance.
	ComponentName string `pulumi:"componentName"`
	// The Oracle base location of Cluster Ready Services (CRS).
	CrsBaseDirectory string `pulumi:"crsBaseDirectory"`
	// The user-friendly name for the cluster instance. The name does not have to be unique.
	DisplayName string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster that the cluster instance belongs to.
	ExternalClusterId         string `pulumi:"externalClusterId"`
	ExternalClusterInstanceId string `pulumi:"externalClusterInstanceId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
	ExternalConnectorId string `pulumi:"externalConnectorId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
	ExternalDbNodeId string `pulumi:"externalDbNodeId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster instance is a part of.
	ExternalDbSystemId string `pulumi:"externalDbSystemId"`
	// The name of the host on which the cluster instance is running.
	HostName string `pulumi:"hostName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster instance.
	Id string `pulumi:"id"`
	// Additional information about the current lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The role of the cluster node.
	NodeRole string `pulumi:"nodeRole"`
	// The current lifecycle state of the external cluster instance.
	State string `pulumi:"state"`
	// The date and time the external cluster instance was created.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the external cluster instance was last updated.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupExternalClusterInstanceOutput(ctx *pulumi.Context, args LookupExternalClusterInstanceOutputArgs, opts ...pulumi.InvokeOption) LookupExternalClusterInstanceResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupExternalClusterInstanceResult, error) {
			args := v.(LookupExternalClusterInstanceArgs)
			r, err := LookupExternalClusterInstance(ctx, &args, opts...)
			var s LookupExternalClusterInstanceResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupExternalClusterInstanceResultOutput)
}

// A collection of arguments for invoking getExternalClusterInstance.
type LookupExternalClusterInstanceOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster instance.
	ExternalClusterInstanceId pulumi.StringInput `pulumi:"externalClusterInstanceId"`
}

func (LookupExternalClusterInstanceOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupExternalClusterInstanceArgs)(nil)).Elem()
}

// A collection of values returned by getExternalClusterInstance.
type LookupExternalClusterInstanceResultOutput struct{ *pulumi.OutputState }

func (LookupExternalClusterInstanceResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupExternalClusterInstanceResult)(nil)).Elem()
}

func (o LookupExternalClusterInstanceResultOutput) ToLookupExternalClusterInstanceResultOutput() LookupExternalClusterInstanceResultOutput {
	return o
}

func (o LookupExternalClusterInstanceResultOutput) ToLookupExternalClusterInstanceResultOutputWithContext(ctx context.Context) LookupExternalClusterInstanceResultOutput {
	return o
}

// The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
func (o LookupExternalClusterInstanceResultOutput) AdrHomeDirectory() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.AdrHomeDirectory }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o LookupExternalClusterInstanceResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The name of the external cluster instance.
func (o LookupExternalClusterInstanceResultOutput) ComponentName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.ComponentName }).(pulumi.StringOutput)
}

// The Oracle base location of Cluster Ready Services (CRS).
func (o LookupExternalClusterInstanceResultOutput) CrsBaseDirectory() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.CrsBaseDirectory }).(pulumi.StringOutput)
}

// The user-friendly name for the cluster instance. The name does not have to be unique.
func (o LookupExternalClusterInstanceResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster that the cluster instance belongs to.
func (o LookupExternalClusterInstanceResultOutput) ExternalClusterId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.ExternalClusterId }).(pulumi.StringOutput)
}

func (o LookupExternalClusterInstanceResultOutput) ExternalClusterInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.ExternalClusterInstanceId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
func (o LookupExternalClusterInstanceResultOutput) ExternalConnectorId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.ExternalConnectorId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
func (o LookupExternalClusterInstanceResultOutput) ExternalDbNodeId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.ExternalDbNodeId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster instance is a part of.
func (o LookupExternalClusterInstanceResultOutput) ExternalDbSystemId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.ExternalDbSystemId }).(pulumi.StringOutput)
}

// The name of the host on which the cluster instance is running.
func (o LookupExternalClusterInstanceResultOutput) HostName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.HostName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster instance.
func (o LookupExternalClusterInstanceResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.Id }).(pulumi.StringOutput)
}

// Additional information about the current lifecycle state.
func (o LookupExternalClusterInstanceResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The role of the cluster node.
func (o LookupExternalClusterInstanceResultOutput) NodeRole() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.NodeRole }).(pulumi.StringOutput)
}

// The current lifecycle state of the external cluster instance.
func (o LookupExternalClusterInstanceResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the external cluster instance was created.
func (o LookupExternalClusterInstanceResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the external cluster instance was last updated.
func (o LookupExternalClusterInstanceResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalClusterInstanceResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupExternalClusterInstanceResultOutput{})
}