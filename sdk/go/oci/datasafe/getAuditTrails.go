// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Audit Trails in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a list of all audit trails.
// The ListAuditTrails operation returns only the audit trails in the specified `compartmentId`.
// The list does not include any subcompartments of the compartmentId passed.
//
// The parameter `accessLevel` specifies whether to return only those compartments for which the
// requestor has INSPECT permissions on at least one resource directly
// or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
// Principal doesn't have access to even one of the child compartments. This is valid only when
// `compartmentIdInSubtree` is set to `true`.
//
// The parameter `compartmentIdInSubtree` applies when you perform ListAuditTrails on the
// `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
// To get a full list of all compartments and subcompartments in the tenancy (root compartment),
// set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.GetAuditTrails(ctx, &datasafe.GetAuditTrailsArgs{
//				CompartmentId:          compartmentId,
//				AccessLevel:            pulumi.StringRef(auditTrailAccessLevel),
//				AuditTrailId:           pulumi.StringRef(testAuditTrail.Id),
//				CompartmentIdInSubtree: pulumi.BoolRef(auditTrailCompartmentIdInSubtree),
//				DisplayName:            pulumi.StringRef(auditTrailDisplayName),
//				State:                  pulumi.StringRef(auditTrailState),
//				Status:                 pulumi.StringRef(auditTrailStatus),
//				TargetId:               pulumi.StringRef(testTarget.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAuditTrails(ctx *pulumi.Context, args *GetAuditTrailsArgs, opts ...pulumi.InvokeOption) (*GetAuditTrailsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetAuditTrailsResult
	err := ctx.Invoke("oci:DataSafe/getAuditTrails:getAuditTrails", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAuditTrails.
type GetAuditTrailsArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel *string `pulumi:"accessLevel"`
	// A optional filter to return only resources that match the specified id.
	AuditTrailId *string `pulumi:"auditTrailId"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree *bool `pulumi:"compartmentIdInSubtree"`
	// A filter to return only resources that match the specified display name.
	DisplayName *string                `pulumi:"displayName"`
	Filters     []GetAuditTrailsFilter `pulumi:"filters"`
	// A optional filter to return only resources that match the specified lifecycle state.
	State *string `pulumi:"state"`
	// A optional filter to return only resources that match the specified sub-state of audit trail.
	Status *string `pulumi:"status"`
	// A filter to return only items related to a specific target OCID.
	TargetId *string `pulumi:"targetId"`
}

// A collection of values returned by getAuditTrails.
type GetAuditTrailsResult struct {
	AccessLevel *string `pulumi:"accessLevel"`
	// The list of audit_trail_collection.
	AuditTrailCollections []GetAuditTrailsAuditTrailCollection `pulumi:"auditTrailCollections"`
	AuditTrailId          *string                              `pulumi:"auditTrailId"`
	// The OCID of the compartment that contains the audit trail and is the same as the compartment of the audit profile resource.
	CompartmentId          string `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool  `pulumi:"compartmentIdInSubtree"`
	// The display name of the audit trail.
	DisplayName *string                `pulumi:"displayName"`
	Filters     []GetAuditTrailsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the audit trail.
	State *string `pulumi:"state"`
	// The current sub-state of the audit trail.
	Status *string `pulumi:"status"`
	// The OCID of the Data Safe target for which the audit trail is created.
	TargetId *string `pulumi:"targetId"`
}

func GetAuditTrailsOutput(ctx *pulumi.Context, args GetAuditTrailsOutputArgs, opts ...pulumi.InvokeOption) GetAuditTrailsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetAuditTrailsResultOutput, error) {
			args := v.(GetAuditTrailsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getAuditTrails:getAuditTrails", args, GetAuditTrailsResultOutput{}, options).(GetAuditTrailsResultOutput), nil
		}).(GetAuditTrailsResultOutput)
}

// A collection of arguments for invoking getAuditTrails.
type GetAuditTrailsOutputArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel pulumi.StringPtrInput `pulumi:"accessLevel"`
	// A optional filter to return only resources that match the specified id.
	AuditTrailId pulumi.StringPtrInput `pulumi:"auditTrailId"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree pulumi.BoolPtrInput `pulumi:"compartmentIdInSubtree"`
	// A filter to return only resources that match the specified display name.
	DisplayName pulumi.StringPtrInput          `pulumi:"displayName"`
	Filters     GetAuditTrailsFilterArrayInput `pulumi:"filters"`
	// A optional filter to return only resources that match the specified lifecycle state.
	State pulumi.StringPtrInput `pulumi:"state"`
	// A optional filter to return only resources that match the specified sub-state of audit trail.
	Status pulumi.StringPtrInput `pulumi:"status"`
	// A filter to return only items related to a specific target OCID.
	TargetId pulumi.StringPtrInput `pulumi:"targetId"`
}

func (GetAuditTrailsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAuditTrailsArgs)(nil)).Elem()
}

// A collection of values returned by getAuditTrails.
type GetAuditTrailsResultOutput struct{ *pulumi.OutputState }

func (GetAuditTrailsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAuditTrailsResult)(nil)).Elem()
}

func (o GetAuditTrailsResultOutput) ToGetAuditTrailsResultOutput() GetAuditTrailsResultOutput {
	return o
}

func (o GetAuditTrailsResultOutput) ToGetAuditTrailsResultOutputWithContext(ctx context.Context) GetAuditTrailsResultOutput {
	return o
}

func (o GetAuditTrailsResultOutput) AccessLevel() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAuditTrailsResult) *string { return v.AccessLevel }).(pulumi.StringPtrOutput)
}

// The list of audit_trail_collection.
func (o GetAuditTrailsResultOutput) AuditTrailCollections() GetAuditTrailsAuditTrailCollectionArrayOutput {
	return o.ApplyT(func(v GetAuditTrailsResult) []GetAuditTrailsAuditTrailCollection { return v.AuditTrailCollections }).(GetAuditTrailsAuditTrailCollectionArrayOutput)
}

func (o GetAuditTrailsResultOutput) AuditTrailId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAuditTrailsResult) *string { return v.AuditTrailId }).(pulumi.StringPtrOutput)
}

// The OCID of the compartment that contains the audit trail and is the same as the compartment of the audit profile resource.
func (o GetAuditTrailsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAuditTrailsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetAuditTrailsResultOutput) CompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetAuditTrailsResult) *bool { return v.CompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

// The display name of the audit trail.
func (o GetAuditTrailsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAuditTrailsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetAuditTrailsResultOutput) Filters() GetAuditTrailsFilterArrayOutput {
	return o.ApplyT(func(v GetAuditTrailsResult) []GetAuditTrailsFilter { return v.Filters }).(GetAuditTrailsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAuditTrailsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAuditTrailsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the audit trail.
func (o GetAuditTrailsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAuditTrailsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The current sub-state of the audit trail.
func (o GetAuditTrailsResultOutput) Status() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAuditTrailsResult) *string { return v.Status }).(pulumi.StringPtrOutput)
}

// The OCID of the Data Safe target for which the audit trail is created.
func (o GetAuditTrailsResultOutput) TargetId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAuditTrailsResult) *string { return v.TargetId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAuditTrailsResultOutput{})
}
