// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package disasterrecovery

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Dr Plan resource in Oracle Cloud Infrastructure Disaster Recovery service.
//
// Get details for the DR Plan identified by *drPlanId*.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DisasterRecovery"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DisasterRecovery.GetDrPlan(ctx, &disasterrecovery.GetDrPlanArgs{
//				DrPlanId: oci_disaster_recovery_dr_plan.Test_dr_plan.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDrPlan(ctx *pulumi.Context, args *LookupDrPlanArgs, opts ...pulumi.InvokeOption) (*LookupDrPlanResult, error) {
	var rv LookupDrPlanResult
	err := ctx.Invoke("oci:DisasterRecovery/getDrPlan:getDrPlan", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDrPlan.
type LookupDrPlanArgs struct {
	// The OCID of the DR Plan.  Example: `ocid1.drplan.oc1.iad.exampleocid`
	DrPlanId string `pulumi:"drPlanId"`
}

// A collection of values returned by getDrPlan.
type LookupDrPlanResult struct {
	// The OCID of the compartment containing the DR Plan.  Example: `ocid1.compartment.oc1..exampleocid1`
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The display name of this DR Plan Group.  Example: `DATABASE_SWITCHOVER`
	DisplayName string `pulumi:"displayName"`
	DrPlanId    string `pulumi:"drPlanId"`
	// The OCID of the DR Protection Group with which this DR Plan is associated.  Example: `ocid1.drplan.oc1.iad.exampleocid2`
	DrProtectionGroupId string `pulumi:"drProtectionGroupId"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The unique id of this step. Must not be modified by the user.  Example: `sgid1.step..examplestepsgid`
	Id string `pulumi:"id"`
	// A message describing the DR Plan's current state in more detail.
	LifeCycleDetails string `pulumi:"lifeCycleDetails"`
	// The OCID of the peer (remote) DR Protection Group associated with this plan's DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid1`
	PeerDrProtectionGroupId string `pulumi:"peerDrProtectionGroupId"`
	// The region of the peer (remote) DR Protection Group associated with this plan's DR Protection Group.  Example: `us-phoenix-1`
	PeerRegion string `pulumi:"peerRegion"`
	// The list of groups in this DR Plan.
	PlanGroups []GetDrPlanPlanGroup `pulumi:"planGroups"`
	// The current state of the DR Plan.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the DR Plan was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the DR Plan was updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
	TimeUpdated string `pulumi:"timeUpdated"`
	// The type of this DR Plan.
	Type string `pulumi:"type"`
}

func LookupDrPlanOutput(ctx *pulumi.Context, args LookupDrPlanOutputArgs, opts ...pulumi.InvokeOption) LookupDrPlanResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupDrPlanResult, error) {
			args := v.(LookupDrPlanArgs)
			r, err := LookupDrPlan(ctx, &args, opts...)
			var s LookupDrPlanResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupDrPlanResultOutput)
}

// A collection of arguments for invoking getDrPlan.
type LookupDrPlanOutputArgs struct {
	// The OCID of the DR Plan.  Example: `ocid1.drplan.oc1.iad.exampleocid`
	DrPlanId pulumi.StringInput `pulumi:"drPlanId"`
}

func (LookupDrPlanOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDrPlanArgs)(nil)).Elem()
}

// A collection of values returned by getDrPlan.
type LookupDrPlanResultOutput struct{ *pulumi.OutputState }

func (LookupDrPlanResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDrPlanResult)(nil)).Elem()
}

func (o LookupDrPlanResultOutput) ToLookupDrPlanResultOutput() LookupDrPlanResultOutput {
	return o
}

func (o LookupDrPlanResultOutput) ToLookupDrPlanResultOutputWithContext(ctx context.Context) LookupDrPlanResultOutput {
	return o
}

// The OCID of the compartment containing the DR Plan.  Example: `ocid1.compartment.oc1..exampleocid1`
func (o LookupDrPlanResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"Operations.CostCenter": "42"}`
func (o LookupDrPlanResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupDrPlanResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// The display name of this DR Plan Group.  Example: `DATABASE_SWITCHOVER`
func (o LookupDrPlanResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

func (o LookupDrPlanResultOutput) DrPlanId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.DrPlanId }).(pulumi.StringOutput)
}

// The OCID of the DR Protection Group with which this DR Plan is associated.  Example: `ocid1.drplan.oc1.iad.exampleocid2`
func (o LookupDrPlanResultOutput) DrProtectionGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.DrProtectionGroupId }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"Department": "Finance"}`
func (o LookupDrPlanResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupDrPlanResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The unique id of this step. Must not be modified by the user.  Example: `sgid1.step..examplestepsgid`
func (o LookupDrPlanResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the DR Plan's current state in more detail.
func (o LookupDrPlanResultOutput) LifeCycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.LifeCycleDetails }).(pulumi.StringOutput)
}

// The OCID of the peer (remote) DR Protection Group associated with this plan's DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid1`
func (o LookupDrPlanResultOutput) PeerDrProtectionGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.PeerDrProtectionGroupId }).(pulumi.StringOutput)
}

// The region of the peer (remote) DR Protection Group associated with this plan's DR Protection Group.  Example: `us-phoenix-1`
func (o LookupDrPlanResultOutput) PeerRegion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.PeerRegion }).(pulumi.StringOutput)
}

// The list of groups in this DR Plan.
func (o LookupDrPlanResultOutput) PlanGroups() GetDrPlanPlanGroupArrayOutput {
	return o.ApplyT(func(v LookupDrPlanResult) []GetDrPlanPlanGroup { return v.PlanGroups }).(GetDrPlanPlanGroupArrayOutput)
}

// The current state of the DR Plan.
func (o LookupDrPlanResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupDrPlanResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupDrPlanResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The date and time the DR Plan was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
func (o LookupDrPlanResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the DR Plan was updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
func (o LookupDrPlanResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The type of this DR Plan.
func (o LookupDrPlanResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDrPlanResult) string { return v.Type }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDrPlanResultOutput{})
}