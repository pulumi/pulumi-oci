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

// This resource provides the User Assessment resource in Oracle Cloud Infrastructure Data Safe service.
//
// Creates a new saved user assessment for one or multiple targets in a compartment. It saves the latest assessments in the
// specified compartment. If a scheduled is passed in, this operation persists the latest assessments that exist at the defined
// date and time, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
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
//			_, err := datasafe.NewUserAssessment(ctx, "test_user_assessment", &datasafe.UserAssessmentArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				TargetId:      pulumi.Any(testTarget.Id),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				Description: pulumi.Any(userAssessmentDescription),
//				DisplayName: pulumi.Any(userAssessmentDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//				IsAssessmentScheduled: pulumi.Any(userAssessmentIsAssessmentScheduled),
//				Schedule:              pulumi.Any(userAssessmentSchedule),
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
// UserAssessments can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DataSafe/userAssessment:UserAssessment test_user_assessment "id"
// ```
type UserAssessment struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment that contains the user assessment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) The description of the user assessment.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The display name of the user assessment.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredAssessmentIds pulumi.StringArrayOutput `pulumi:"ignoredAssessmentIds"`
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredTargets UserAssessmentIgnoredTargetArrayOutput `pulumi:"ignoredTargets"`
	// (Updatable) Indicates whether the assessment is scheduled to run.
	IsAssessmentScheduled pulumi.BoolOutput `pulumi:"isAssessmentScheduled"`
	// Indicates if the user assessment is set as a baseline. This is applicable only to saved user assessments.
	IsBaseline pulumi.BoolOutput `pulumi:"isBaseline"`
	// Indicates if the user assessment deviates from the baseline.
	IsDeviatedFromBaseline pulumi.BoolOutput `pulumi:"isDeviatedFromBaseline"`
	// The OCID of the last user assessment baseline against which the latest assessment was compared.
	LastComparedBaselineId pulumi.StringOutput `pulumi:"lastComparedBaselineId"`
	// Details about the current state of the user assessment.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// (Updatable) To schedule the assessment for saving periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
	//
	// Allowed version strings - "v1" v1's version specific schedule -<ss> <mm> <hh> <day-of-week> <day-of-month> Each of the above fields potentially introduce constraints. A workrequest is created only when clock time satisfies all the constraints. Constraints introduced: 1. seconds = <ss> (So, the allowed range for <ss> is [0, 59]) 2. minutes = <mm> (So, the allowed range for <mm> is [0, 59]) 3. hours = <hh> (So, the allowed range for <hh> is [0, 23]) <day-of-week> can be either '*' (without quotes or a number between 1(Monday) and 7(Sunday)) 4. No constraint introduced when it is '*'. When not, day of week must equal the given value <day-of-month> can be either '*' (without quotes or a number between 1 and 28) 5. No constraint introduced when it is '*'. When not, day of month must equal the given value
	Schedule pulumi.StringOutput `pulumi:"schedule"`
	// The OCID of the user assessment that is responsible for creating this scheduled save assessment.
	ScheduleAssessmentId pulumi.StringOutput `pulumi:"scheduleAssessmentId"`
	// The current state of the user assessment.
	State pulumi.StringOutput `pulumi:"state"`
	// Map that contains maps of values. Example: `{"Operations": {"CostCenter": "42"}}`
	Statistics pulumi.StringOutput `pulumi:"statistics"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The OCID of the target database on which the user assessment is to be run.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId pulumi.StringOutput `pulumi:"targetId"`
	// Array of database target OCIDs.
	TargetIds pulumi.StringArrayOutput `pulumi:"targetIds"`
	// The date and time the user assessment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the user assessment was last executed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeLastAssessed pulumi.StringOutput `pulumi:"timeLastAssessed"`
	// The date and time the user assessment was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// Indicates whether the user assessment was created by the system or the user.
	TriggeredBy pulumi.StringOutput `pulumi:"triggeredBy"`
	// The type of the user assessment. The possible types are:
	Type pulumi.StringOutput `pulumi:"type"`
}

// NewUserAssessment registers a new resource with the given unique name, arguments, and options.
func NewUserAssessment(ctx *pulumi.Context,
	name string, args *UserAssessmentArgs, opts ...pulumi.ResourceOption) (*UserAssessment, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.TargetId == nil {
		return nil, errors.New("invalid value for required argument 'TargetId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource UserAssessment
	err := ctx.RegisterResource("oci:DataSafe/userAssessment:UserAssessment", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetUserAssessment gets an existing UserAssessment resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetUserAssessment(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *UserAssessmentState, opts ...pulumi.ResourceOption) (*UserAssessment, error) {
	var resource UserAssessment
	err := ctx.ReadResource("oci:DataSafe/userAssessment:UserAssessment", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering UserAssessment resources.
type userAssessmentState struct {
	// (Updatable) The OCID of the compartment that contains the user assessment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The description of the user assessment.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the user assessment.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredAssessmentIds []string `pulumi:"ignoredAssessmentIds"`
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredTargets []UserAssessmentIgnoredTarget `pulumi:"ignoredTargets"`
	// (Updatable) Indicates whether the assessment is scheduled to run.
	IsAssessmentScheduled *bool `pulumi:"isAssessmentScheduled"`
	// Indicates if the user assessment is set as a baseline. This is applicable only to saved user assessments.
	IsBaseline *bool `pulumi:"isBaseline"`
	// Indicates if the user assessment deviates from the baseline.
	IsDeviatedFromBaseline *bool `pulumi:"isDeviatedFromBaseline"`
	// The OCID of the last user assessment baseline against which the latest assessment was compared.
	LastComparedBaselineId *string `pulumi:"lastComparedBaselineId"`
	// Details about the current state of the user assessment.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// (Updatable) To schedule the assessment for saving periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
	//
	// Allowed version strings - "v1" v1's version specific schedule -<ss> <mm> <hh> <day-of-week> <day-of-month> Each of the above fields potentially introduce constraints. A workrequest is created only when clock time satisfies all the constraints. Constraints introduced: 1. seconds = <ss> (So, the allowed range for <ss> is [0, 59]) 2. minutes = <mm> (So, the allowed range for <mm> is [0, 59]) 3. hours = <hh> (So, the allowed range for <hh> is [0, 23]) <day-of-week> can be either '*' (without quotes or a number between 1(Monday) and 7(Sunday)) 4. No constraint introduced when it is '*'. When not, day of week must equal the given value <day-of-month> can be either '*' (without quotes or a number between 1 and 28) 5. No constraint introduced when it is '*'. When not, day of month must equal the given value
	Schedule *string `pulumi:"schedule"`
	// The OCID of the user assessment that is responsible for creating this scheduled save assessment.
	ScheduleAssessmentId *string `pulumi:"scheduleAssessmentId"`
	// The current state of the user assessment.
	State *string `pulumi:"state"`
	// Map that contains maps of values. Example: `{"Operations": {"CostCenter": "42"}}`
	Statistics *string `pulumi:"statistics"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The OCID of the target database on which the user assessment is to be run.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId *string `pulumi:"targetId"`
	// Array of database target OCIDs.
	TargetIds []string `pulumi:"targetIds"`
	// The date and time the user assessment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the user assessment was last executed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeLastAssessed *string `pulumi:"timeLastAssessed"`
	// The date and time the user assessment was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
	// Indicates whether the user assessment was created by the system or the user.
	TriggeredBy *string `pulumi:"triggeredBy"`
	// The type of the user assessment. The possible types are:
	Type *string `pulumi:"type"`
}

type UserAssessmentState struct {
	// (Updatable) The OCID of the compartment that contains the user assessment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The description of the user assessment.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the user assessment.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredAssessmentIds pulumi.StringArrayInput
	// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
	IgnoredTargets UserAssessmentIgnoredTargetArrayInput
	// (Updatable) Indicates whether the assessment is scheduled to run.
	IsAssessmentScheduled pulumi.BoolPtrInput
	// Indicates if the user assessment is set as a baseline. This is applicable only to saved user assessments.
	IsBaseline pulumi.BoolPtrInput
	// Indicates if the user assessment deviates from the baseline.
	IsDeviatedFromBaseline pulumi.BoolPtrInput
	// The OCID of the last user assessment baseline against which the latest assessment was compared.
	LastComparedBaselineId pulumi.StringPtrInput
	// Details about the current state of the user assessment.
	LifecycleDetails pulumi.StringPtrInput
	// (Updatable) To schedule the assessment for saving periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
	//
	// Allowed version strings - "v1" v1's version specific schedule -<ss> <mm> <hh> <day-of-week> <day-of-month> Each of the above fields potentially introduce constraints. A workrequest is created only when clock time satisfies all the constraints. Constraints introduced: 1. seconds = <ss> (So, the allowed range for <ss> is [0, 59]) 2. minutes = <mm> (So, the allowed range for <mm> is [0, 59]) 3. hours = <hh> (So, the allowed range for <hh> is [0, 23]) <day-of-week> can be either '*' (without quotes or a number between 1(Monday) and 7(Sunday)) 4. No constraint introduced when it is '*'. When not, day of week must equal the given value <day-of-month> can be either '*' (without quotes or a number between 1 and 28) 5. No constraint introduced when it is '*'. When not, day of month must equal the given value
	Schedule pulumi.StringPtrInput
	// The OCID of the user assessment that is responsible for creating this scheduled save assessment.
	ScheduleAssessmentId pulumi.StringPtrInput
	// The current state of the user assessment.
	State pulumi.StringPtrInput
	// Map that contains maps of values. Example: `{"Operations": {"CostCenter": "42"}}`
	Statistics pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The OCID of the target database on which the user assessment is to be run.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId pulumi.StringPtrInput
	// Array of database target OCIDs.
	TargetIds pulumi.StringArrayInput
	// The date and time the user assessment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The date and time the user assessment was last executed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeLastAssessed pulumi.StringPtrInput
	// The date and time the user assessment was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated pulumi.StringPtrInput
	// Indicates whether the user assessment was created by the system or the user.
	TriggeredBy pulumi.StringPtrInput
	// The type of the user assessment. The possible types are:
	Type pulumi.StringPtrInput
}

func (UserAssessmentState) ElementType() reflect.Type {
	return reflect.TypeOf((*userAssessmentState)(nil)).Elem()
}

type userAssessmentArgs struct {
	// (Updatable) The OCID of the compartment that contains the user assessment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The description of the user assessment.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the user assessment.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Indicates whether the assessment is scheduled to run.
	IsAssessmentScheduled *bool `pulumi:"isAssessmentScheduled"`
	// (Updatable) To schedule the assessment for saving periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
	//
	// Allowed version strings - "v1" v1's version specific schedule -<ss> <mm> <hh> <day-of-week> <day-of-month> Each of the above fields potentially introduce constraints. A workrequest is created only when clock time satisfies all the constraints. Constraints introduced: 1. seconds = <ss> (So, the allowed range for <ss> is [0, 59]) 2. minutes = <mm> (So, the allowed range for <mm> is [0, 59]) 3. hours = <hh> (So, the allowed range for <hh> is [0, 23]) <day-of-week> can be either '*' (without quotes or a number between 1(Monday) and 7(Sunday)) 4. No constraint introduced when it is '*'. When not, day of week must equal the given value <day-of-month> can be either '*' (without quotes or a number between 1 and 28) 5. No constraint introduced when it is '*'. When not, day of month must equal the given value
	Schedule *string `pulumi:"schedule"`
	// The OCID of the target database on which the user assessment is to be run.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId string `pulumi:"targetId"`
}

// The set of arguments for constructing a UserAssessment resource.
type UserAssessmentArgs struct {
	// (Updatable) The OCID of the compartment that contains the user assessment.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The description of the user assessment.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the user assessment.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) Indicates whether the assessment is scheduled to run.
	IsAssessmentScheduled pulumi.BoolPtrInput
	// (Updatable) To schedule the assessment for saving periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
	//
	// Allowed version strings - "v1" v1's version specific schedule -<ss> <mm> <hh> <day-of-week> <day-of-month> Each of the above fields potentially introduce constraints. A workrequest is created only when clock time satisfies all the constraints. Constraints introduced: 1. seconds = <ss> (So, the allowed range for <ss> is [0, 59]) 2. minutes = <mm> (So, the allowed range for <mm> is [0, 59]) 3. hours = <hh> (So, the allowed range for <hh> is [0, 23]) <day-of-week> can be either '*' (without quotes or a number between 1(Monday) and 7(Sunday)) 4. No constraint introduced when it is '*'. When not, day of week must equal the given value <day-of-month> can be either '*' (without quotes or a number between 1 and 28) 5. No constraint introduced when it is '*'. When not, day of month must equal the given value
	Schedule pulumi.StringPtrInput
	// The OCID of the target database on which the user assessment is to be run.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId pulumi.StringInput
}

func (UserAssessmentArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*userAssessmentArgs)(nil)).Elem()
}

type UserAssessmentInput interface {
	pulumi.Input

	ToUserAssessmentOutput() UserAssessmentOutput
	ToUserAssessmentOutputWithContext(ctx context.Context) UserAssessmentOutput
}

func (*UserAssessment) ElementType() reflect.Type {
	return reflect.TypeOf((**UserAssessment)(nil)).Elem()
}

func (i *UserAssessment) ToUserAssessmentOutput() UserAssessmentOutput {
	return i.ToUserAssessmentOutputWithContext(context.Background())
}

func (i *UserAssessment) ToUserAssessmentOutputWithContext(ctx context.Context) UserAssessmentOutput {
	return pulumi.ToOutputWithContext(ctx, i).(UserAssessmentOutput)
}

// UserAssessmentArrayInput is an input type that accepts UserAssessmentArray and UserAssessmentArrayOutput values.
// You can construct a concrete instance of `UserAssessmentArrayInput` via:
//
//	UserAssessmentArray{ UserAssessmentArgs{...} }
type UserAssessmentArrayInput interface {
	pulumi.Input

	ToUserAssessmentArrayOutput() UserAssessmentArrayOutput
	ToUserAssessmentArrayOutputWithContext(context.Context) UserAssessmentArrayOutput
}

type UserAssessmentArray []UserAssessmentInput

func (UserAssessmentArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*UserAssessment)(nil)).Elem()
}

func (i UserAssessmentArray) ToUserAssessmentArrayOutput() UserAssessmentArrayOutput {
	return i.ToUserAssessmentArrayOutputWithContext(context.Background())
}

func (i UserAssessmentArray) ToUserAssessmentArrayOutputWithContext(ctx context.Context) UserAssessmentArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(UserAssessmentArrayOutput)
}

// UserAssessmentMapInput is an input type that accepts UserAssessmentMap and UserAssessmentMapOutput values.
// You can construct a concrete instance of `UserAssessmentMapInput` via:
//
//	UserAssessmentMap{ "key": UserAssessmentArgs{...} }
type UserAssessmentMapInput interface {
	pulumi.Input

	ToUserAssessmentMapOutput() UserAssessmentMapOutput
	ToUserAssessmentMapOutputWithContext(context.Context) UserAssessmentMapOutput
}

type UserAssessmentMap map[string]UserAssessmentInput

func (UserAssessmentMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*UserAssessment)(nil)).Elem()
}

func (i UserAssessmentMap) ToUserAssessmentMapOutput() UserAssessmentMapOutput {
	return i.ToUserAssessmentMapOutputWithContext(context.Background())
}

func (i UserAssessmentMap) ToUserAssessmentMapOutputWithContext(ctx context.Context) UserAssessmentMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(UserAssessmentMapOutput)
}

type UserAssessmentOutput struct{ *pulumi.OutputState }

func (UserAssessmentOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**UserAssessment)(nil)).Elem()
}

func (o UserAssessmentOutput) ToUserAssessmentOutput() UserAssessmentOutput {
	return o
}

func (o UserAssessmentOutput) ToUserAssessmentOutputWithContext(ctx context.Context) UserAssessmentOutput {
	return o
}

// (Updatable) The OCID of the compartment that contains the user assessment.
func (o UserAssessmentOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
func (o UserAssessmentOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) The description of the user assessment.
func (o UserAssessmentOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) The display name of the user assessment.
func (o UserAssessmentOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o UserAssessmentOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
func (o UserAssessmentOutput) IgnoredAssessmentIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringArrayOutput { return v.IgnoredAssessmentIds }).(pulumi.StringArrayOutput)
}

// List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
func (o UserAssessmentOutput) IgnoredTargets() UserAssessmentIgnoredTargetArrayOutput {
	return o.ApplyT(func(v *UserAssessment) UserAssessmentIgnoredTargetArrayOutput { return v.IgnoredTargets }).(UserAssessmentIgnoredTargetArrayOutput)
}

// (Updatable) Indicates whether the assessment is scheduled to run.
func (o UserAssessmentOutput) IsAssessmentScheduled() pulumi.BoolOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.BoolOutput { return v.IsAssessmentScheduled }).(pulumi.BoolOutput)
}

// Indicates if the user assessment is set as a baseline. This is applicable only to saved user assessments.
func (o UserAssessmentOutput) IsBaseline() pulumi.BoolOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.BoolOutput { return v.IsBaseline }).(pulumi.BoolOutput)
}

// Indicates if the user assessment deviates from the baseline.
func (o UserAssessmentOutput) IsDeviatedFromBaseline() pulumi.BoolOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.BoolOutput { return v.IsDeviatedFromBaseline }).(pulumi.BoolOutput)
}

// The OCID of the last user assessment baseline against which the latest assessment was compared.
func (o UserAssessmentOutput) LastComparedBaselineId() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.LastComparedBaselineId }).(pulumi.StringOutput)
}

// Details about the current state of the user assessment.
func (o UserAssessmentOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// (Updatable) To schedule the assessment for saving periodically, specify the schedule in this attribute. Create or schedule one assessment per compartment. If not defined, the assessment runs immediately. Format - <version-string>;<version-specific-schedule>
//
// Allowed version strings - "v1" v1's version specific schedule -<ss> <mm> <hh> <day-of-week> <day-of-month> Each of the above fields potentially introduce constraints. A workrequest is created only when clock time satisfies all the constraints. Constraints introduced: 1. seconds = <ss> (So, the allowed range for <ss> is [0, 59]) 2. minutes = <mm> (So, the allowed range for <mm> is [0, 59]) 3. hours = <hh> (So, the allowed range for <hh> is [0, 23]) <day-of-week> can be either '*' (without quotes or a number between 1(Monday) and 7(Sunday)) 4. No constraint introduced when it is '*'. When not, day of week must equal the given value <day-of-month> can be either '*' (without quotes or a number between 1 and 28) 5. No constraint introduced when it is '*'. When not, day of month must equal the given value
func (o UserAssessmentOutput) Schedule() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.Schedule }).(pulumi.StringOutput)
}

// The OCID of the user assessment that is responsible for creating this scheduled save assessment.
func (o UserAssessmentOutput) ScheduleAssessmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.ScheduleAssessmentId }).(pulumi.StringOutput)
}

// The current state of the user assessment.
func (o UserAssessmentOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Map that contains maps of values. Example: `{"Operations": {"CostCenter": "42"}}`
func (o UserAssessmentOutput) Statistics() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.Statistics }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o UserAssessmentOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The OCID of the target database on which the user assessment is to be run.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o UserAssessmentOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.TargetId }).(pulumi.StringOutput)
}

// Array of database target OCIDs.
func (o UserAssessmentOutput) TargetIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringArrayOutput { return v.TargetIds }).(pulumi.StringArrayOutput)
}

// The date and time the user assessment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o UserAssessmentOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the user assessment was last executed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o UserAssessmentOutput) TimeLastAssessed() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.TimeLastAssessed }).(pulumi.StringOutput)
}

// The date and time the user assessment was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o UserAssessmentOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// Indicates whether the user assessment was created by the system or the user.
func (o UserAssessmentOutput) TriggeredBy() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.TriggeredBy }).(pulumi.StringOutput)
}

// The type of the user assessment. The possible types are:
func (o UserAssessmentOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v *UserAssessment) pulumi.StringOutput { return v.Type }).(pulumi.StringOutput)
}

type UserAssessmentArrayOutput struct{ *pulumi.OutputState }

func (UserAssessmentArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*UserAssessment)(nil)).Elem()
}

func (o UserAssessmentArrayOutput) ToUserAssessmentArrayOutput() UserAssessmentArrayOutput {
	return o
}

func (o UserAssessmentArrayOutput) ToUserAssessmentArrayOutputWithContext(ctx context.Context) UserAssessmentArrayOutput {
	return o
}

func (o UserAssessmentArrayOutput) Index(i pulumi.IntInput) UserAssessmentOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *UserAssessment {
		return vs[0].([]*UserAssessment)[vs[1].(int)]
	}).(UserAssessmentOutput)
}

type UserAssessmentMapOutput struct{ *pulumi.OutputState }

func (UserAssessmentMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*UserAssessment)(nil)).Elem()
}

func (o UserAssessmentMapOutput) ToUserAssessmentMapOutput() UserAssessmentMapOutput {
	return o
}

func (o UserAssessmentMapOutput) ToUserAssessmentMapOutputWithContext(ctx context.Context) UserAssessmentMapOutput {
	return o
}

func (o UserAssessmentMapOutput) MapIndex(k pulumi.StringInput) UserAssessmentOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *UserAssessment {
		return vs[0].(map[string]*UserAssessment)[vs[1].(string)]
	}).(UserAssessmentOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*UserAssessmentInput)(nil)).Elem(), &UserAssessment{})
	pulumi.RegisterInputType(reflect.TypeOf((*UserAssessmentArrayInput)(nil)).Elem(), UserAssessmentArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*UserAssessmentMapInput)(nil)).Elem(), UserAssessmentMap{})
	pulumi.RegisterOutputType(UserAssessmentOutput{})
	pulumi.RegisterOutputType(UserAssessmentArrayOutput{})
	pulumi.RegisterOutputType(UserAssessmentMapOutput{})
}
