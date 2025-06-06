// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Audit Archive Retrieval resource in Oracle Cloud Infrastructure Data Safe service.
//
// Creates a work request to retrieve archived audit data. This asynchronous process will usually take over an hour to complete.
// Save the id from the response of this operation. Call GetAuditArchiveRetrieval operation after an hour, passing the id to know the status of
// this operation.
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
//			_, err := datasafe.NewAuditArchiveRetrieval(ctx, "test_audit_archive_retrieval", &datasafe.AuditArchiveRetrievalArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				EndDate:       pulumi.Any(auditArchiveRetrievalEndDate),
//				StartDate:     pulumi.Any(auditArchiveRetrievalStartDate),
//				TargetId:      pulumi.Any(testTarget.Id),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				Description: pulumi.Any(auditArchiveRetrievalDescription),
//				DisplayName: pulumi.Any(auditArchiveRetrievalDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// AuditArchiveRetrievals can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DataSafe/auditArchiveRetrieval:AuditArchiveRetrieval test_audit_archive_retrieval "id"
// ```
type AuditArchiveRetrieval struct {
	pulumi.CustomResourceState

	// Total count of audit events to be retrieved from the archive for the specified date range.
	AuditEventCount pulumi.StringOutput `pulumi:"auditEventCount"`
	// (Updatable) The OCID of the compartment that contains the archival retrieval.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Description of the archive retrieval.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The display name of the archive retrieval. The name does not have to be unique, and is changeable.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// End month of the archive retrieval, in the format defined by RFC3339.
	EndDate pulumi.StringOutput `pulumi:"endDate"`
	// The Error details of a failed archive retrieval.
	ErrorInfo pulumi.StringOutput `pulumi:"errorInfo"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// Details about the current state of the archive retrieval.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Start month of the archive retrieval, in the format defined by RFC3339.
	StartDate pulumi.StringOutput `pulumi:"startDate"`
	// The current state of the archive retrieval.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The OCID of the target associated with the archive retrieval.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId pulumi.StringOutput `pulumi:"targetId"`
	// The date time when archive retrieval request was fulfilled, in the format defined by RFC3339.
	TimeCompleted pulumi.StringOutput `pulumi:"timeCompleted"`
	// The date time when retrieved archive data will be deleted from Data Safe and unloaded back into archival.
	TimeOfExpiry pulumi.StringOutput `pulumi:"timeOfExpiry"`
	// The date time when archive retrieval was requested, in the format defined by RFC3339.
	TimeRequested pulumi.StringOutput `pulumi:"timeRequested"`
}

// NewAuditArchiveRetrieval registers a new resource with the given unique name, arguments, and options.
func NewAuditArchiveRetrieval(ctx *pulumi.Context,
	name string, args *AuditArchiveRetrievalArgs, opts ...pulumi.ResourceOption) (*AuditArchiveRetrieval, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.EndDate == nil {
		return nil, errors.New("invalid value for required argument 'EndDate'")
	}
	if args.StartDate == nil {
		return nil, errors.New("invalid value for required argument 'StartDate'")
	}
	if args.TargetId == nil {
		return nil, errors.New("invalid value for required argument 'TargetId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource AuditArchiveRetrieval
	err := ctx.RegisterResource("oci:DataSafe/auditArchiveRetrieval:AuditArchiveRetrieval", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAuditArchiveRetrieval gets an existing AuditArchiveRetrieval resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAuditArchiveRetrieval(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AuditArchiveRetrievalState, opts ...pulumi.ResourceOption) (*AuditArchiveRetrieval, error) {
	var resource AuditArchiveRetrieval
	err := ctx.ReadResource("oci:DataSafe/auditArchiveRetrieval:AuditArchiveRetrieval", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering AuditArchiveRetrieval resources.
type auditArchiveRetrievalState struct {
	// Total count of audit events to be retrieved from the archive for the specified date range.
	AuditEventCount *string `pulumi:"auditEventCount"`
	// (Updatable) The OCID of the compartment that contains the archival retrieval.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Description of the archive retrieval.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the archive retrieval. The name does not have to be unique, and is changeable.
	DisplayName *string `pulumi:"displayName"`
	// End month of the archive retrieval, in the format defined by RFC3339.
	EndDate *string `pulumi:"endDate"`
	// The Error details of a failed archive retrieval.
	ErrorInfo *string `pulumi:"errorInfo"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Details about the current state of the archive retrieval.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Start month of the archive retrieval, in the format defined by RFC3339.
	StartDate *string `pulumi:"startDate"`
	// The current state of the archive retrieval.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The OCID of the target associated with the archive retrieval.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId *string `pulumi:"targetId"`
	// The date time when archive retrieval request was fulfilled, in the format defined by RFC3339.
	TimeCompleted *string `pulumi:"timeCompleted"`
	// The date time when retrieved archive data will be deleted from Data Safe and unloaded back into archival.
	TimeOfExpiry *string `pulumi:"timeOfExpiry"`
	// The date time when archive retrieval was requested, in the format defined by RFC3339.
	TimeRequested *string `pulumi:"timeRequested"`
}

type AuditArchiveRetrievalState struct {
	// Total count of audit events to be retrieved from the archive for the specified date range.
	AuditEventCount pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment that contains the archival retrieval.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Description of the archive retrieval.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the archive retrieval. The name does not have to be unique, and is changeable.
	DisplayName pulumi.StringPtrInput
	// End month of the archive retrieval, in the format defined by RFC3339.
	EndDate pulumi.StringPtrInput
	// The Error details of a failed archive retrieval.
	ErrorInfo pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// Details about the current state of the archive retrieval.
	LifecycleDetails pulumi.StringPtrInput
	// Start month of the archive retrieval, in the format defined by RFC3339.
	StartDate pulumi.StringPtrInput
	// The current state of the archive retrieval.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The OCID of the target associated with the archive retrieval.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId pulumi.StringPtrInput
	// The date time when archive retrieval request was fulfilled, in the format defined by RFC3339.
	TimeCompleted pulumi.StringPtrInput
	// The date time when retrieved archive data will be deleted from Data Safe and unloaded back into archival.
	TimeOfExpiry pulumi.StringPtrInput
	// The date time when archive retrieval was requested, in the format defined by RFC3339.
	TimeRequested pulumi.StringPtrInput
}

func (AuditArchiveRetrievalState) ElementType() reflect.Type {
	return reflect.TypeOf((*auditArchiveRetrievalState)(nil)).Elem()
}

type auditArchiveRetrievalArgs struct {
	// (Updatable) The OCID of the compartment that contains the archival retrieval.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Description of the archive retrieval.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the archive retrieval. The name does not have to be unique, and is changeable.
	DisplayName *string `pulumi:"displayName"`
	// End month of the archive retrieval, in the format defined by RFC3339.
	EndDate string `pulumi:"endDate"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Start month of the archive retrieval, in the format defined by RFC3339.
	StartDate string `pulumi:"startDate"`
	// The OCID of the target associated with the archive retrieval.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId string `pulumi:"targetId"`
}

// The set of arguments for constructing a AuditArchiveRetrieval resource.
type AuditArchiveRetrievalArgs struct {
	// (Updatable) The OCID of the compartment that contains the archival retrieval.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Description of the archive retrieval.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the archive retrieval. The name does not have to be unique, and is changeable.
	DisplayName pulumi.StringPtrInput
	// End month of the archive retrieval, in the format defined by RFC3339.
	EndDate pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// Start month of the archive retrieval, in the format defined by RFC3339.
	StartDate pulumi.StringInput
	// The OCID of the target associated with the archive retrieval.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId pulumi.StringInput
}

func (AuditArchiveRetrievalArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*auditArchiveRetrievalArgs)(nil)).Elem()
}

type AuditArchiveRetrievalInput interface {
	pulumi.Input

	ToAuditArchiveRetrievalOutput() AuditArchiveRetrievalOutput
	ToAuditArchiveRetrievalOutputWithContext(ctx context.Context) AuditArchiveRetrievalOutput
}

func (*AuditArchiveRetrieval) ElementType() reflect.Type {
	return reflect.TypeOf((**AuditArchiveRetrieval)(nil)).Elem()
}

func (i *AuditArchiveRetrieval) ToAuditArchiveRetrievalOutput() AuditArchiveRetrievalOutput {
	return i.ToAuditArchiveRetrievalOutputWithContext(context.Background())
}

func (i *AuditArchiveRetrieval) ToAuditArchiveRetrievalOutputWithContext(ctx context.Context) AuditArchiveRetrievalOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AuditArchiveRetrievalOutput)
}

// AuditArchiveRetrievalArrayInput is an input type that accepts AuditArchiveRetrievalArray and AuditArchiveRetrievalArrayOutput values.
// You can construct a concrete instance of `AuditArchiveRetrievalArrayInput` via:
//
//	AuditArchiveRetrievalArray{ AuditArchiveRetrievalArgs{...} }
type AuditArchiveRetrievalArrayInput interface {
	pulumi.Input

	ToAuditArchiveRetrievalArrayOutput() AuditArchiveRetrievalArrayOutput
	ToAuditArchiveRetrievalArrayOutputWithContext(context.Context) AuditArchiveRetrievalArrayOutput
}

type AuditArchiveRetrievalArray []AuditArchiveRetrievalInput

func (AuditArchiveRetrievalArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AuditArchiveRetrieval)(nil)).Elem()
}

func (i AuditArchiveRetrievalArray) ToAuditArchiveRetrievalArrayOutput() AuditArchiveRetrievalArrayOutput {
	return i.ToAuditArchiveRetrievalArrayOutputWithContext(context.Background())
}

func (i AuditArchiveRetrievalArray) ToAuditArchiveRetrievalArrayOutputWithContext(ctx context.Context) AuditArchiveRetrievalArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AuditArchiveRetrievalArrayOutput)
}

// AuditArchiveRetrievalMapInput is an input type that accepts AuditArchiveRetrievalMap and AuditArchiveRetrievalMapOutput values.
// You can construct a concrete instance of `AuditArchiveRetrievalMapInput` via:
//
//	AuditArchiveRetrievalMap{ "key": AuditArchiveRetrievalArgs{...} }
type AuditArchiveRetrievalMapInput interface {
	pulumi.Input

	ToAuditArchiveRetrievalMapOutput() AuditArchiveRetrievalMapOutput
	ToAuditArchiveRetrievalMapOutputWithContext(context.Context) AuditArchiveRetrievalMapOutput
}

type AuditArchiveRetrievalMap map[string]AuditArchiveRetrievalInput

func (AuditArchiveRetrievalMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AuditArchiveRetrieval)(nil)).Elem()
}

func (i AuditArchiveRetrievalMap) ToAuditArchiveRetrievalMapOutput() AuditArchiveRetrievalMapOutput {
	return i.ToAuditArchiveRetrievalMapOutputWithContext(context.Background())
}

func (i AuditArchiveRetrievalMap) ToAuditArchiveRetrievalMapOutputWithContext(ctx context.Context) AuditArchiveRetrievalMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AuditArchiveRetrievalMapOutput)
}

type AuditArchiveRetrievalOutput struct{ *pulumi.OutputState }

func (AuditArchiveRetrievalOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**AuditArchiveRetrieval)(nil)).Elem()
}

func (o AuditArchiveRetrievalOutput) ToAuditArchiveRetrievalOutput() AuditArchiveRetrievalOutput {
	return o
}

func (o AuditArchiveRetrievalOutput) ToAuditArchiveRetrievalOutputWithContext(ctx context.Context) AuditArchiveRetrievalOutput {
	return o
}

// Total count of audit events to be retrieved from the archive for the specified date range.
func (o AuditArchiveRetrievalOutput) AuditEventCount() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.AuditEventCount }).(pulumi.StringOutput)
}

// (Updatable) The OCID of the compartment that contains the archival retrieval.
func (o AuditArchiveRetrievalOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
func (o AuditArchiveRetrievalOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Description of the archive retrieval.
func (o AuditArchiveRetrievalOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) The display name of the archive retrieval. The name does not have to be unique, and is changeable.
func (o AuditArchiveRetrievalOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// End month of the archive retrieval, in the format defined by RFC3339.
func (o AuditArchiveRetrievalOutput) EndDate() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.EndDate }).(pulumi.StringOutput)
}

// The Error details of a failed archive retrieval.
func (o AuditArchiveRetrievalOutput) ErrorInfo() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.ErrorInfo }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o AuditArchiveRetrievalOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Details about the current state of the archive retrieval.
func (o AuditArchiveRetrievalOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Start month of the archive retrieval, in the format defined by RFC3339.
func (o AuditArchiveRetrievalOutput) StartDate() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.StartDate }).(pulumi.StringOutput)
}

// The current state of the archive retrieval.
func (o AuditArchiveRetrievalOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o AuditArchiveRetrievalOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The OCID of the target associated with the archive retrieval.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o AuditArchiveRetrievalOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.TargetId }).(pulumi.StringOutput)
}

// The date time when archive retrieval request was fulfilled, in the format defined by RFC3339.
func (o AuditArchiveRetrievalOutput) TimeCompleted() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.TimeCompleted }).(pulumi.StringOutput)
}

// The date time when retrieved archive data will be deleted from Data Safe and unloaded back into archival.
func (o AuditArchiveRetrievalOutput) TimeOfExpiry() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.TimeOfExpiry }).(pulumi.StringOutput)
}

// The date time when archive retrieval was requested, in the format defined by RFC3339.
func (o AuditArchiveRetrievalOutput) TimeRequested() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditArchiveRetrieval) pulumi.StringOutput { return v.TimeRequested }).(pulumi.StringOutput)
}

type AuditArchiveRetrievalArrayOutput struct{ *pulumi.OutputState }

func (AuditArchiveRetrievalArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AuditArchiveRetrieval)(nil)).Elem()
}

func (o AuditArchiveRetrievalArrayOutput) ToAuditArchiveRetrievalArrayOutput() AuditArchiveRetrievalArrayOutput {
	return o
}

func (o AuditArchiveRetrievalArrayOutput) ToAuditArchiveRetrievalArrayOutputWithContext(ctx context.Context) AuditArchiveRetrievalArrayOutput {
	return o
}

func (o AuditArchiveRetrievalArrayOutput) Index(i pulumi.IntInput) AuditArchiveRetrievalOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *AuditArchiveRetrieval {
		return vs[0].([]*AuditArchiveRetrieval)[vs[1].(int)]
	}).(AuditArchiveRetrievalOutput)
}

type AuditArchiveRetrievalMapOutput struct{ *pulumi.OutputState }

func (AuditArchiveRetrievalMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AuditArchiveRetrieval)(nil)).Elem()
}

func (o AuditArchiveRetrievalMapOutput) ToAuditArchiveRetrievalMapOutput() AuditArchiveRetrievalMapOutput {
	return o
}

func (o AuditArchiveRetrievalMapOutput) ToAuditArchiveRetrievalMapOutputWithContext(ctx context.Context) AuditArchiveRetrievalMapOutput {
	return o
}

func (o AuditArchiveRetrievalMapOutput) MapIndex(k pulumi.StringInput) AuditArchiveRetrievalOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *AuditArchiveRetrieval {
		return vs[0].(map[string]*AuditArchiveRetrieval)[vs[1].(string)]
	}).(AuditArchiveRetrievalOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*AuditArchiveRetrievalInput)(nil)).Elem(), &AuditArchiveRetrieval{})
	pulumi.RegisterInputType(reflect.TypeOf((*AuditArchiveRetrievalArrayInput)(nil)).Elem(), AuditArchiveRetrievalArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*AuditArchiveRetrievalMapInput)(nil)).Elem(), AuditArchiveRetrievalMap{})
	pulumi.RegisterOutputType(AuditArchiveRetrievalOutput{})
	pulumi.RegisterOutputType(AuditArchiveRetrievalArrayOutput{})
	pulumi.RegisterOutputType(AuditArchiveRetrievalMapOutput{})
}
