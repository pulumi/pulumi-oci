// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Security Assessment resource in Oracle Cloud Infrastructure Data Safe service.
//
// Creates a new saved security assessment for one or multiple targets in a compartment. When this operation is performed,
// it will save the latest assessments in the specified compartment. If a schedule is passed, it will persist the latest assessments,
// at the defined date and time, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataSafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DataSafe.NewSecurityAssessment(ctx, "testSecurityAssessment", &DataSafe.SecurityAssessmentArgs{
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				TargetId:      pulumi.Any(oci_cloud_guard_target.Test_target.Id),
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				Description: pulumi.Any(_var.Security_assessment_description),
//				DisplayName: pulumi.Any(_var.Security_assessment_display_name),
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
//				},
//				Schedule: pulumi.Any(_var.Security_assessment_schedule),
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
// SecurityAssessments can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:DataSafe/securityAssessment:SecurityAssessment test_security_assessment "id"
//
// ```
type SecurityAssessment struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment that contains the security assessment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Description of the security assessment.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The display name of the security assessment.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredAssessmentIds pulumi.StringArrayOutput `pulumi:"ignoredAssessmentIds"`
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredTargets pulumi.StringArrayOutput `pulumi:"ignoredTargets"`
	// Indicates whether or not the security assessment is set as a baseline. This is applicable only for saved security assessments.
	IsBaseline pulumi.BoolOutput `pulumi:"isBaseline"`
	// Indicates whether or not the security assessment deviates from the baseline.
	IsDeviatedFromBaseline pulumi.BoolOutput `pulumi:"isDeviatedFromBaseline"`
	// The OCID of the baseline against which the latest security assessment was compared.
	LastComparedBaselineId pulumi.StringOutput `pulumi:"lastComparedBaselineId"`
	// Details about the current state of the security assessment.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The summary of findings for the security assessment.
	Link pulumi.StringOutput `pulumi:"link"`
	// (Updatable) To schedule the assessment for running periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
	Schedule pulumi.StringOutput `pulumi:"schedule"`
	// The OCID of the security assessment that is responsible for creating this scheduled save assessment.
	ScheduleSecurityAssessmentId pulumi.StringOutput `pulumi:"scheduleSecurityAssessmentId"`
	// The current state of the security assessment.
	State pulumi.StringOutput `pulumi:"state"`
	// Statistics showing the number of findings for each category grouped by risk levels for all the targets in the specified security assessment.
	Statistics SecurityAssessmentStatisticArrayOutput `pulumi:"statistics"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The OCID of the target database on which security assessment is to be run.
	TargetId pulumi.StringOutput `pulumi:"targetId"`
	// Array of database target OCIDs.
	TargetIds pulumi.StringArrayOutput `pulumi:"targetIds"`
	// The version of the target database.
	TargetVersion pulumi.StringOutput `pulumi:"targetVersion"`
	// The date and time when the security assessment was created. Conforms to the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time when the security assessment was last updated. Conforms to the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// Indicates whether the security assessment was created by system or by a user.
	TriggeredBy pulumi.StringOutput `pulumi:"triggeredBy"`
	// The type of this security assessment. The possible types are:
	Type pulumi.StringOutput `pulumi:"type"`
}

// NewSecurityAssessment registers a new resource with the given unique name, arguments, and options.
func NewSecurityAssessment(ctx *pulumi.Context,
	name string, args *SecurityAssessmentArgs, opts ...pulumi.ResourceOption) (*SecurityAssessment, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.TargetId == nil {
		return nil, errors.New("invalid value for required argument 'TargetId'")
	}
	var resource SecurityAssessment
	err := ctx.RegisterResource("oci:DataSafe/securityAssessment:SecurityAssessment", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSecurityAssessment gets an existing SecurityAssessment resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSecurityAssessment(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SecurityAssessmentState, opts ...pulumi.ResourceOption) (*SecurityAssessment, error) {
	var resource SecurityAssessment
	err := ctx.ReadResource("oci:DataSafe/securityAssessment:SecurityAssessment", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering SecurityAssessment resources.
type securityAssessmentState struct {
	// (Updatable) The OCID of the compartment that contains the security assessment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Description of the security assessment.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the security assessment.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredAssessmentIds []string `pulumi:"ignoredAssessmentIds"`
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredTargets []string `pulumi:"ignoredTargets"`
	// Indicates whether or not the security assessment is set as a baseline. This is applicable only for saved security assessments.
	IsBaseline *bool `pulumi:"isBaseline"`
	// Indicates whether or not the security assessment deviates from the baseline.
	IsDeviatedFromBaseline *bool `pulumi:"isDeviatedFromBaseline"`
	// The OCID of the baseline against which the latest security assessment was compared.
	LastComparedBaselineId *string `pulumi:"lastComparedBaselineId"`
	// Details about the current state of the security assessment.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The summary of findings for the security assessment.
	Link *string `pulumi:"link"`
	// (Updatable) To schedule the assessment for running periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
	Schedule *string `pulumi:"schedule"`
	// The OCID of the security assessment that is responsible for creating this scheduled save assessment.
	ScheduleSecurityAssessmentId *string `pulumi:"scheduleSecurityAssessmentId"`
	// The current state of the security assessment.
	State *string `pulumi:"state"`
	// Statistics showing the number of findings for each category grouped by risk levels for all the targets in the specified security assessment.
	Statistics []SecurityAssessmentStatistic `pulumi:"statistics"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The OCID of the target database on which security assessment is to be run.
	TargetId *string `pulumi:"targetId"`
	// Array of database target OCIDs.
	TargetIds []string `pulumi:"targetIds"`
	// The version of the target database.
	TargetVersion *string `pulumi:"targetVersion"`
	// The date and time when the security assessment was created. Conforms to the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time when the security assessment was last updated. Conforms to the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
	// Indicates whether the security assessment was created by system or by a user.
	TriggeredBy *string `pulumi:"triggeredBy"`
	// The type of this security assessment. The possible types are:
	Type *string `pulumi:"type"`
}

type SecurityAssessmentState struct {
	// (Updatable) The OCID of the compartment that contains the security assessment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Description of the security assessment.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the security assessment.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredAssessmentIds pulumi.StringArrayInput
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredTargets pulumi.StringArrayInput
	// Indicates whether or not the security assessment is set as a baseline. This is applicable only for saved security assessments.
	IsBaseline pulumi.BoolPtrInput
	// Indicates whether or not the security assessment deviates from the baseline.
	IsDeviatedFromBaseline pulumi.BoolPtrInput
	// The OCID of the baseline against which the latest security assessment was compared.
	LastComparedBaselineId pulumi.StringPtrInput
	// Details about the current state of the security assessment.
	LifecycleDetails pulumi.StringPtrInput
	// The summary of findings for the security assessment.
	Link pulumi.StringPtrInput
	// (Updatable) To schedule the assessment for running periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
	Schedule pulumi.StringPtrInput
	// The OCID of the security assessment that is responsible for creating this scheduled save assessment.
	ScheduleSecurityAssessmentId pulumi.StringPtrInput
	// The current state of the security assessment.
	State pulumi.StringPtrInput
	// Statistics showing the number of findings for each category grouped by risk levels for all the targets in the specified security assessment.
	Statistics SecurityAssessmentStatisticArrayInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The OCID of the target database on which security assessment is to be run.
	TargetId pulumi.StringPtrInput
	// Array of database target OCIDs.
	TargetIds pulumi.StringArrayInput
	// The version of the target database.
	TargetVersion pulumi.StringPtrInput
	// The date and time when the security assessment was created. Conforms to the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The date and time when the security assessment was last updated. Conforms to the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated pulumi.StringPtrInput
	// Indicates whether the security assessment was created by system or by a user.
	TriggeredBy pulumi.StringPtrInput
	// The type of this security assessment. The possible types are:
	Type pulumi.StringPtrInput
}

func (SecurityAssessmentState) ElementType() reflect.Type {
	return reflect.TypeOf((*securityAssessmentState)(nil)).Elem()
}

type securityAssessmentArgs struct {
	// (Updatable) The OCID of the compartment that contains the security assessment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Description of the security assessment.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the security assessment.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) To schedule the assessment for running periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
	Schedule *string `pulumi:"schedule"`
	// The OCID of the target database on which security assessment is to be run.
	TargetId string `pulumi:"targetId"`
}

// The set of arguments for constructing a SecurityAssessment resource.
type SecurityAssessmentArgs struct {
	// (Updatable) The OCID of the compartment that contains the security assessment.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Description of the security assessment.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the security assessment.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) To schedule the assessment for running periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
	Schedule pulumi.StringPtrInput
	// The OCID of the target database on which security assessment is to be run.
	TargetId pulumi.StringInput
}

func (SecurityAssessmentArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*securityAssessmentArgs)(nil)).Elem()
}

type SecurityAssessmentInput interface {
	pulumi.Input

	ToSecurityAssessmentOutput() SecurityAssessmentOutput
	ToSecurityAssessmentOutputWithContext(ctx context.Context) SecurityAssessmentOutput
}

func (*SecurityAssessment) ElementType() reflect.Type {
	return reflect.TypeOf((**SecurityAssessment)(nil)).Elem()
}

func (i *SecurityAssessment) ToSecurityAssessmentOutput() SecurityAssessmentOutput {
	return i.ToSecurityAssessmentOutputWithContext(context.Background())
}

func (i *SecurityAssessment) ToSecurityAssessmentOutputWithContext(ctx context.Context) SecurityAssessmentOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SecurityAssessmentOutput)
}

// SecurityAssessmentArrayInput is an input type that accepts SecurityAssessmentArray and SecurityAssessmentArrayOutput values.
// You can construct a concrete instance of `SecurityAssessmentArrayInput` via:
//
//	SecurityAssessmentArray{ SecurityAssessmentArgs{...} }
type SecurityAssessmentArrayInput interface {
	pulumi.Input

	ToSecurityAssessmentArrayOutput() SecurityAssessmentArrayOutput
	ToSecurityAssessmentArrayOutputWithContext(context.Context) SecurityAssessmentArrayOutput
}

type SecurityAssessmentArray []SecurityAssessmentInput

func (SecurityAssessmentArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SecurityAssessment)(nil)).Elem()
}

func (i SecurityAssessmentArray) ToSecurityAssessmentArrayOutput() SecurityAssessmentArrayOutput {
	return i.ToSecurityAssessmentArrayOutputWithContext(context.Background())
}

func (i SecurityAssessmentArray) ToSecurityAssessmentArrayOutputWithContext(ctx context.Context) SecurityAssessmentArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SecurityAssessmentArrayOutput)
}

// SecurityAssessmentMapInput is an input type that accepts SecurityAssessmentMap and SecurityAssessmentMapOutput values.
// You can construct a concrete instance of `SecurityAssessmentMapInput` via:
//
//	SecurityAssessmentMap{ "key": SecurityAssessmentArgs{...} }
type SecurityAssessmentMapInput interface {
	pulumi.Input

	ToSecurityAssessmentMapOutput() SecurityAssessmentMapOutput
	ToSecurityAssessmentMapOutputWithContext(context.Context) SecurityAssessmentMapOutput
}

type SecurityAssessmentMap map[string]SecurityAssessmentInput

func (SecurityAssessmentMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SecurityAssessment)(nil)).Elem()
}

func (i SecurityAssessmentMap) ToSecurityAssessmentMapOutput() SecurityAssessmentMapOutput {
	return i.ToSecurityAssessmentMapOutputWithContext(context.Background())
}

func (i SecurityAssessmentMap) ToSecurityAssessmentMapOutputWithContext(ctx context.Context) SecurityAssessmentMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SecurityAssessmentMapOutput)
}

type SecurityAssessmentOutput struct{ *pulumi.OutputState }

func (SecurityAssessmentOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**SecurityAssessment)(nil)).Elem()
}

func (o SecurityAssessmentOutput) ToSecurityAssessmentOutput() SecurityAssessmentOutput {
	return o
}

func (o SecurityAssessmentOutput) ToSecurityAssessmentOutputWithContext(ctx context.Context) SecurityAssessmentOutput {
	return o
}

// (Updatable) The OCID of the compartment that contains the security assessment.
func (o SecurityAssessmentOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
func (o SecurityAssessmentOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) Description of the security assessment.
func (o SecurityAssessmentOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) The display name of the security assessment.
func (o SecurityAssessmentOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o SecurityAssessmentOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
func (o SecurityAssessmentOutput) IgnoredAssessmentIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringArrayOutput { return v.IgnoredAssessmentIds }).(pulumi.StringArrayOutput)
}

// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
func (o SecurityAssessmentOutput) IgnoredTargets() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringArrayOutput { return v.IgnoredTargets }).(pulumi.StringArrayOutput)
}

// Indicates whether or not the security assessment is set as a baseline. This is applicable only for saved security assessments.
func (o SecurityAssessmentOutput) IsBaseline() pulumi.BoolOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.BoolOutput { return v.IsBaseline }).(pulumi.BoolOutput)
}

// Indicates whether or not the security assessment deviates from the baseline.
func (o SecurityAssessmentOutput) IsDeviatedFromBaseline() pulumi.BoolOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.BoolOutput { return v.IsDeviatedFromBaseline }).(pulumi.BoolOutput)
}

// The OCID of the baseline against which the latest security assessment was compared.
func (o SecurityAssessmentOutput) LastComparedBaselineId() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.LastComparedBaselineId }).(pulumi.StringOutput)
}

// Details about the current state of the security assessment.
func (o SecurityAssessmentOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The summary of findings for the security assessment.
func (o SecurityAssessmentOutput) Link() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.Link }).(pulumi.StringOutput)
}

// (Updatable) To schedule the assessment for running periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
func (o SecurityAssessmentOutput) Schedule() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.Schedule }).(pulumi.StringOutput)
}

// The OCID of the security assessment that is responsible for creating this scheduled save assessment.
func (o SecurityAssessmentOutput) ScheduleSecurityAssessmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.ScheduleSecurityAssessmentId }).(pulumi.StringOutput)
}

// The current state of the security assessment.
func (o SecurityAssessmentOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Statistics showing the number of findings for each category grouped by risk levels for all the targets in the specified security assessment.
func (o SecurityAssessmentOutput) Statistics() SecurityAssessmentStatisticArrayOutput {
	return o.ApplyT(func(v *SecurityAssessment) SecurityAssessmentStatisticArrayOutput { return v.Statistics }).(SecurityAssessmentStatisticArrayOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o SecurityAssessmentOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// The OCID of the target database on which security assessment is to be run.
func (o SecurityAssessmentOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.TargetId }).(pulumi.StringOutput)
}

// Array of database target OCIDs.
func (o SecurityAssessmentOutput) TargetIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringArrayOutput { return v.TargetIds }).(pulumi.StringArrayOutput)
}

// The version of the target database.
func (o SecurityAssessmentOutput) TargetVersion() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.TargetVersion }).(pulumi.StringOutput)
}

// The date and time when the security assessment was created. Conforms to the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o SecurityAssessmentOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time when the security assessment was last updated. Conforms to the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o SecurityAssessmentOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// Indicates whether the security assessment was created by system or by a user.
func (o SecurityAssessmentOutput) TriggeredBy() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.TriggeredBy }).(pulumi.StringOutput)
}

// The type of this security assessment. The possible types are:
func (o SecurityAssessmentOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityAssessment) pulumi.StringOutput { return v.Type }).(pulumi.StringOutput)
}

type SecurityAssessmentArrayOutput struct{ *pulumi.OutputState }

func (SecurityAssessmentArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SecurityAssessment)(nil)).Elem()
}

func (o SecurityAssessmentArrayOutput) ToSecurityAssessmentArrayOutput() SecurityAssessmentArrayOutput {
	return o
}

func (o SecurityAssessmentArrayOutput) ToSecurityAssessmentArrayOutputWithContext(ctx context.Context) SecurityAssessmentArrayOutput {
	return o
}

func (o SecurityAssessmentArrayOutput) Index(i pulumi.IntInput) SecurityAssessmentOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *SecurityAssessment {
		return vs[0].([]*SecurityAssessment)[vs[1].(int)]
	}).(SecurityAssessmentOutput)
}

type SecurityAssessmentMapOutput struct{ *pulumi.OutputState }

func (SecurityAssessmentMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SecurityAssessment)(nil)).Elem()
}

func (o SecurityAssessmentMapOutput) ToSecurityAssessmentMapOutput() SecurityAssessmentMapOutput {
	return o
}

func (o SecurityAssessmentMapOutput) ToSecurityAssessmentMapOutputWithContext(ctx context.Context) SecurityAssessmentMapOutput {
	return o
}

func (o SecurityAssessmentMapOutput) MapIndex(k pulumi.StringInput) SecurityAssessmentOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *SecurityAssessment {
		return vs[0].(map[string]*SecurityAssessment)[vs[1].(string)]
	}).(SecurityAssessmentOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*SecurityAssessmentInput)(nil)).Elem(), &SecurityAssessment{})
	pulumi.RegisterInputType(reflect.TypeOf((*SecurityAssessmentArrayInput)(nil)).Elem(), SecurityAssessmentArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*SecurityAssessmentMapInput)(nil)).Elem(), SecurityAssessmentMap{})
	pulumi.RegisterOutputType(SecurityAssessmentOutput{})
	pulumi.RegisterOutputType(SecurityAssessmentArrayOutput{})
	pulumi.RegisterOutputType(SecurityAssessmentMapOutput{})
}