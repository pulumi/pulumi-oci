// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dataintegration

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Workspace resource in Oracle Cloud Infrastructure Data Integration service.
//
// Retrieves a Data Integration workspace using the specified identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataIntegration"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DataIntegration.GetWorkspace(ctx, &dataintegration.GetWorkspaceArgs{
//				WorkspaceId: oci_dataintegration_workspace.Test_workspace.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupWorkspace(ctx *pulumi.Context, args *LookupWorkspaceArgs, opts ...pulumi.InvokeOption) (*LookupWorkspaceResult, error) {
	var rv LookupWorkspaceResult
	err := ctx.Invoke("oci:DataIntegration/getWorkspace:getWorkspace", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getWorkspace.
type LookupWorkspaceArgs struct {
	// The workspace ID.
	WorkspaceId string `pulumi:"workspaceId"`
}

// A collection of values returned by getWorkspace.
type LookupWorkspaceResult struct {
	// The OCID of the compartment that contains the workspace.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A user defined description for the workspace.
	Description string `pulumi:"description"`
	// A user-friendly display name for the workspace. Does not have to be unique, and can be modified. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// The IP of the custom DNS.
	DnsServerIp string `pulumi:"dnsServerIp"`
	// The DNS zone of the custom DNS to use to resolve names.
	DnsServerZone string `pulumi:"dnsServerZone"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A system-generated and immutable identifier assigned to the workspace upon creation.
	Id               string `pulumi:"id"`
	IsForceOperation bool   `pulumi:"isForceOperation"`
	// Specifies whether the private network connection is enabled or disabled.
	IsPrivateNetworkEnabled bool `pulumi:"isPrivateNetworkEnabled"`
	QuiesceTimeout          int  `pulumi:"quiesceTimeout"`
	// Lifecycle states for workspaces in Data Integration Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn't available FAILED   - The resource is in a failed state due to validation or other errors STARTING - The resource is being started and may not be usable until becomes ACTIVE again STOPPING - The resource is in the process of Stopping and may not be usable until it Stops or fails STOPPED  - The resource is in Stopped state due to stop operation.
	State string `pulumi:"state"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
	StateMessage string `pulumi:"stateMessage"`
	// The OCID of the subnet for customer connected databases.
	SubnetId string `pulumi:"subnetId"`
	// The date and time the workspace was created, in the timestamp format defined by RFC3339.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the workspace was updated, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated string `pulumi:"timeUpdated"`
	// The OCID of the VCN the subnet is in.
	VcnId       string `pulumi:"vcnId"`
	WorkspaceId string `pulumi:"workspaceId"`
}

func LookupWorkspaceOutput(ctx *pulumi.Context, args LookupWorkspaceOutputArgs, opts ...pulumi.InvokeOption) LookupWorkspaceResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupWorkspaceResult, error) {
			args := v.(LookupWorkspaceArgs)
			r, err := LookupWorkspace(ctx, &args, opts...)
			var s LookupWorkspaceResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupWorkspaceResultOutput)
}

// A collection of arguments for invoking getWorkspace.
type LookupWorkspaceOutputArgs struct {
	// The workspace ID.
	WorkspaceId pulumi.StringInput `pulumi:"workspaceId"`
}

func (LookupWorkspaceOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupWorkspaceArgs)(nil)).Elem()
}

// A collection of values returned by getWorkspace.
type LookupWorkspaceResultOutput struct{ *pulumi.OutputState }

func (LookupWorkspaceResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupWorkspaceResult)(nil)).Elem()
}

func (o LookupWorkspaceResultOutput) ToLookupWorkspaceResultOutput() LookupWorkspaceResultOutput {
	return o
}

func (o LookupWorkspaceResultOutput) ToLookupWorkspaceResultOutputWithContext(ctx context.Context) LookupWorkspaceResultOutput {
	return o
}

// The OCID of the compartment that contains the workspace.
func (o LookupWorkspaceResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupWorkspaceResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A user defined description for the workspace.
func (o LookupWorkspaceResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.Description }).(pulumi.StringOutput)
}

// A user-friendly display name for the workspace. Does not have to be unique, and can be modified. Avoid entering confidential information.
func (o LookupWorkspaceResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The IP of the custom DNS.
func (o LookupWorkspaceResultOutput) DnsServerIp() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.DnsServerIp }).(pulumi.StringOutput)
}

// The DNS zone of the custom DNS to use to resolve names.
func (o LookupWorkspaceResultOutput) DnsServerZone() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.DnsServerZone }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupWorkspaceResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// A system-generated and immutable identifier assigned to the workspace upon creation.
func (o LookupWorkspaceResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupWorkspaceResultOutput) IsForceOperation() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) bool { return v.IsForceOperation }).(pulumi.BoolOutput)
}

// Specifies whether the private network connection is enabled or disabled.
func (o LookupWorkspaceResultOutput) IsPrivateNetworkEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) bool { return v.IsPrivateNetworkEnabled }).(pulumi.BoolOutput)
}

func (o LookupWorkspaceResultOutput) QuiesceTimeout() pulumi.IntOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) int { return v.QuiesceTimeout }).(pulumi.IntOutput)
}

// Lifecycle states for workspaces in Data Integration Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn't available FAILED   - The resource is in a failed state due to validation or other errors STARTING - The resource is being started and may not be usable until becomes ACTIVE again STOPPING - The resource is in the process of Stopping and may not be usable until it Stops or fails STOPPED  - The resource is in Stopped state due to stop operation.
func (o LookupWorkspaceResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.State }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
func (o LookupWorkspaceResultOutput) StateMessage() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.StateMessage }).(pulumi.StringOutput)
}

// The OCID of the subnet for customer connected databases.
func (o LookupWorkspaceResultOutput) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.SubnetId }).(pulumi.StringOutput)
}

// The date and time the workspace was created, in the timestamp format defined by RFC3339.
func (o LookupWorkspaceResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the workspace was updated, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o LookupWorkspaceResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The OCID of the VCN the subnet is in.
func (o LookupWorkspaceResultOutput) VcnId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.VcnId }).(pulumi.StringOutput)
}

func (o LookupWorkspaceResultOutput) WorkspaceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupWorkspaceResult) string { return v.WorkspaceId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupWorkspaceResultOutput{})
}