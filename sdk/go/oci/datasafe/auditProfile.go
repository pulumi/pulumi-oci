// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Audit Profile resource in Oracle Cloud Infrastructure Data Safe service.
//
// Updates one or more attributes of the specified audit profile.
//
// ## Import
//
// AuditProfiles can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:DataSafe/auditProfile:AuditProfile test_audit_profile "id"
//
// ```
type AuditProfile struct {
	pulumi.CustomResourceState

	// Indicates number of audit records collected by Data Safe in the current calendar month.  Audit records for the Data Safe service account are excluded and are not counted towards your monthly free limit.
	AuditCollectedVolume pulumi.StringOutput `pulumi:"auditCollectedVolume"`
	// The OCID of the audit.
	AuditProfileId pulumi.StringOutput `pulumi:"auditProfileId"`
	// Indicates the list of available audit trails on the target.
	AuditTrails AuditProfileAuditTrailArrayOutput `pulumi:"auditTrails"`
	// (Updatable) An optional property when incremented triggers Change Retention. Could be set to any integer value.
	ChangeRetentionTrigger pulumi.IntPtrOutput `pulumi:"changeRetentionTrigger"`
	// (Updatable) The OCID of the compartment that contains the audit.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The description of the audit profile.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The display name of the audit profile. The name does not have to be unique, and it's changeable.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Indicates whether audit retention settings like online and offline months is set at the target level overriding the global audit retention settings.
	IsOverrideGlobalRetentionSetting pulumi.BoolOutput `pulumi:"isOverrideGlobalRetentionSetting"`
	// (Updatable) Indicates if you want to continue collecting audit records beyond the free limit of one million audit records per month per target database, potentially incurring additional charges. The default value is inherited from the global settings.  You can change at the global level or at the target level.
	IsPaidUsageEnabled pulumi.BoolOutput `pulumi:"isPaidUsageEnabled"`
	// Details about the current state of the audit profile in Data Safe.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Indicates the number of months the audit records will be stored offline in the Data Safe audit archive. Minimum: 0; Maximum: 72 months. If you have a requirement to store the audit data even longer in archive, please contact the Oracle Support.
	OfflineMonths pulumi.IntOutput `pulumi:"offlineMonths"`
	// Indicates the number of months the audit records will be stored online in Oracle Data Safe audit repository for immediate reporting and analysis.  Minimum: 1; Maximum:12 months
	OnlineMonths pulumi.IntOutput `pulumi:"onlineMonths"`
	// The current state of the audit profile.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The OCID of the Data Safe target for which the audit profile is created.
	TargetId pulumi.StringOutput `pulumi:"targetId"`
	// The date and time the audit profile was created, in the format defined by RFC3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the audit profile was updated, in the format defined by RFC3339.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewAuditProfile registers a new resource with the given unique name, arguments, and options.
func NewAuditProfile(ctx *pulumi.Context,
	name string, args *AuditProfileArgs, opts ...pulumi.ResourceOption) (*AuditProfile, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AuditProfileId == nil {
		return nil, errors.New("invalid value for required argument 'AuditProfileId'")
	}
	var resource AuditProfile
	err := ctx.RegisterResource("oci:DataSafe/auditProfile:AuditProfile", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAuditProfile gets an existing AuditProfile resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAuditProfile(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AuditProfileState, opts ...pulumi.ResourceOption) (*AuditProfile, error) {
	var resource AuditProfile
	err := ctx.ReadResource("oci:DataSafe/auditProfile:AuditProfile", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering AuditProfile resources.
type auditProfileState struct {
	// Indicates number of audit records collected by Data Safe in the current calendar month.  Audit records for the Data Safe service account are excluded and are not counted towards your monthly free limit.
	AuditCollectedVolume *string `pulumi:"auditCollectedVolume"`
	// The OCID of the audit.
	AuditProfileId *string `pulumi:"auditProfileId"`
	// Indicates the list of available audit trails on the target.
	AuditTrails []AuditProfileAuditTrail `pulumi:"auditTrails"`
	// (Updatable) An optional property when incremented triggers Change Retention. Could be set to any integer value.
	ChangeRetentionTrigger *int `pulumi:"changeRetentionTrigger"`
	// (Updatable) The OCID of the compartment that contains the audit.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the audit profile.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the audit profile. The name does not have to be unique, and it's changeable.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Indicates whether audit retention settings like online and offline months is set at the target level overriding the global audit retention settings.
	IsOverrideGlobalRetentionSetting *bool `pulumi:"isOverrideGlobalRetentionSetting"`
	// (Updatable) Indicates if you want to continue collecting audit records beyond the free limit of one million audit records per month per target database, potentially incurring additional charges. The default value is inherited from the global settings.  You can change at the global level or at the target level.
	IsPaidUsageEnabled *bool `pulumi:"isPaidUsageEnabled"`
	// Details about the current state of the audit profile in Data Safe.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Indicates the number of months the audit records will be stored offline in the Data Safe audit archive. Minimum: 0; Maximum: 72 months. If you have a requirement to store the audit data even longer in archive, please contact the Oracle Support.
	OfflineMonths *int `pulumi:"offlineMonths"`
	// Indicates the number of months the audit records will be stored online in Oracle Data Safe audit repository for immediate reporting and analysis.  Minimum: 1; Maximum:12 months
	OnlineMonths *int `pulumi:"onlineMonths"`
	// The current state of the audit profile.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The OCID of the Data Safe target for which the audit profile is created.
	TargetId *string `pulumi:"targetId"`
	// The date and time the audit profile was created, in the format defined by RFC3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the audit profile was updated, in the format defined by RFC3339.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type AuditProfileState struct {
	// Indicates number of audit records collected by Data Safe in the current calendar month.  Audit records for the Data Safe service account are excluded and are not counted towards your monthly free limit.
	AuditCollectedVolume pulumi.StringPtrInput
	// The OCID of the audit.
	AuditProfileId pulumi.StringPtrInput
	// Indicates the list of available audit trails on the target.
	AuditTrails AuditProfileAuditTrailArrayInput
	// (Updatable) An optional property when incremented triggers Change Retention. Could be set to any integer value.
	ChangeRetentionTrigger pulumi.IntPtrInput
	// (Updatable) The OCID of the compartment that contains the audit.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the audit profile.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the audit profile. The name does not have to be unique, and it's changeable.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Indicates whether audit retention settings like online and offline months is set at the target level overriding the global audit retention settings.
	IsOverrideGlobalRetentionSetting pulumi.BoolPtrInput
	// (Updatable) Indicates if you want to continue collecting audit records beyond the free limit of one million audit records per month per target database, potentially incurring additional charges. The default value is inherited from the global settings.  You can change at the global level or at the target level.
	IsPaidUsageEnabled pulumi.BoolPtrInput
	// Details about the current state of the audit profile in Data Safe.
	LifecycleDetails pulumi.StringPtrInput
	// Indicates the number of months the audit records will be stored offline in the Data Safe audit archive. Minimum: 0; Maximum: 72 months. If you have a requirement to store the audit data even longer in archive, please contact the Oracle Support.
	OfflineMonths pulumi.IntPtrInput
	// Indicates the number of months the audit records will be stored online in Oracle Data Safe audit repository for immediate reporting and analysis.  Minimum: 1; Maximum:12 months
	OnlineMonths pulumi.IntPtrInput
	// The current state of the audit profile.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The OCID of the Data Safe target for which the audit profile is created.
	TargetId pulumi.StringPtrInput
	// The date and time the audit profile was created, in the format defined by RFC3339.
	TimeCreated pulumi.StringPtrInput
	// The date and time the audit profile was updated, in the format defined by RFC3339.
	TimeUpdated pulumi.StringPtrInput
}

func (AuditProfileState) ElementType() reflect.Type {
	return reflect.TypeOf((*auditProfileState)(nil)).Elem()
}

type auditProfileArgs struct {
	// The OCID of the audit.
	AuditProfileId string `pulumi:"auditProfileId"`
	// (Updatable) An optional property when incremented triggers Change Retention. Could be set to any integer value.
	ChangeRetentionTrigger *int `pulumi:"changeRetentionTrigger"`
	// (Updatable) The OCID of the compartment that contains the audit.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the audit profile.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the audit profile. The name does not have to be unique, and it's changeable.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Indicates if you want to continue collecting audit records beyond the free limit of one million audit records per month per target database, potentially incurring additional charges. The default value is inherited from the global settings.  You can change at the global level or at the target level.
	IsPaidUsageEnabled *bool `pulumi:"isPaidUsageEnabled"`
}

// The set of arguments for constructing a AuditProfile resource.
type AuditProfileArgs struct {
	// The OCID of the audit.
	AuditProfileId pulumi.StringInput
	// (Updatable) An optional property when incremented triggers Change Retention. Could be set to any integer value.
	ChangeRetentionTrigger pulumi.IntPtrInput
	// (Updatable) The OCID of the compartment that contains the audit.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the audit profile.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the audit profile. The name does not have to be unique, and it's changeable.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Indicates if you want to continue collecting audit records beyond the free limit of one million audit records per month per target database, potentially incurring additional charges. The default value is inherited from the global settings.  You can change at the global level or at the target level.
	IsPaidUsageEnabled pulumi.BoolPtrInput
}

func (AuditProfileArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*auditProfileArgs)(nil)).Elem()
}

type AuditProfileInput interface {
	pulumi.Input

	ToAuditProfileOutput() AuditProfileOutput
	ToAuditProfileOutputWithContext(ctx context.Context) AuditProfileOutput
}

func (*AuditProfile) ElementType() reflect.Type {
	return reflect.TypeOf((**AuditProfile)(nil)).Elem()
}

func (i *AuditProfile) ToAuditProfileOutput() AuditProfileOutput {
	return i.ToAuditProfileOutputWithContext(context.Background())
}

func (i *AuditProfile) ToAuditProfileOutputWithContext(ctx context.Context) AuditProfileOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AuditProfileOutput)
}

// AuditProfileArrayInput is an input type that accepts AuditProfileArray and AuditProfileArrayOutput values.
// You can construct a concrete instance of `AuditProfileArrayInput` via:
//
//	AuditProfileArray{ AuditProfileArgs{...} }
type AuditProfileArrayInput interface {
	pulumi.Input

	ToAuditProfileArrayOutput() AuditProfileArrayOutput
	ToAuditProfileArrayOutputWithContext(context.Context) AuditProfileArrayOutput
}

type AuditProfileArray []AuditProfileInput

func (AuditProfileArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AuditProfile)(nil)).Elem()
}

func (i AuditProfileArray) ToAuditProfileArrayOutput() AuditProfileArrayOutput {
	return i.ToAuditProfileArrayOutputWithContext(context.Background())
}

func (i AuditProfileArray) ToAuditProfileArrayOutputWithContext(ctx context.Context) AuditProfileArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AuditProfileArrayOutput)
}

// AuditProfileMapInput is an input type that accepts AuditProfileMap and AuditProfileMapOutput values.
// You can construct a concrete instance of `AuditProfileMapInput` via:
//
//	AuditProfileMap{ "key": AuditProfileArgs{...} }
type AuditProfileMapInput interface {
	pulumi.Input

	ToAuditProfileMapOutput() AuditProfileMapOutput
	ToAuditProfileMapOutputWithContext(context.Context) AuditProfileMapOutput
}

type AuditProfileMap map[string]AuditProfileInput

func (AuditProfileMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AuditProfile)(nil)).Elem()
}

func (i AuditProfileMap) ToAuditProfileMapOutput() AuditProfileMapOutput {
	return i.ToAuditProfileMapOutputWithContext(context.Background())
}

func (i AuditProfileMap) ToAuditProfileMapOutputWithContext(ctx context.Context) AuditProfileMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AuditProfileMapOutput)
}

type AuditProfileOutput struct{ *pulumi.OutputState }

func (AuditProfileOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**AuditProfile)(nil)).Elem()
}

func (o AuditProfileOutput) ToAuditProfileOutput() AuditProfileOutput {
	return o
}

func (o AuditProfileOutput) ToAuditProfileOutputWithContext(ctx context.Context) AuditProfileOutput {
	return o
}

// Indicates number of audit records collected by Data Safe in the current calendar month.  Audit records for the Data Safe service account are excluded and are not counted towards your monthly free limit.
func (o AuditProfileOutput) AuditCollectedVolume() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.StringOutput { return v.AuditCollectedVolume }).(pulumi.StringOutput)
}

// The OCID of the audit.
func (o AuditProfileOutput) AuditProfileId() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.StringOutput { return v.AuditProfileId }).(pulumi.StringOutput)
}

// Indicates the list of available audit trails on the target.
func (o AuditProfileOutput) AuditTrails() AuditProfileAuditTrailArrayOutput {
	return o.ApplyT(func(v *AuditProfile) AuditProfileAuditTrailArrayOutput { return v.AuditTrails }).(AuditProfileAuditTrailArrayOutput)
}

// (Updatable) An optional property when incremented triggers Change Retention. Could be set to any integer value.
func (o AuditProfileOutput) ChangeRetentionTrigger() pulumi.IntPtrOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.IntPtrOutput { return v.ChangeRetentionTrigger }).(pulumi.IntPtrOutput)
}

// (Updatable) The OCID of the compartment that contains the audit.
func (o AuditProfileOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
func (o AuditProfileOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) The description of the audit profile.
func (o AuditProfileOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) The display name of the audit profile. The name does not have to be unique, and it's changeable.
func (o AuditProfileOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o AuditProfileOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// Indicates whether audit retention settings like online and offline months is set at the target level overriding the global audit retention settings.
func (o AuditProfileOutput) IsOverrideGlobalRetentionSetting() pulumi.BoolOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.BoolOutput { return v.IsOverrideGlobalRetentionSetting }).(pulumi.BoolOutput)
}

// (Updatable) Indicates if you want to continue collecting audit records beyond the free limit of one million audit records per month per target database, potentially incurring additional charges. The default value is inherited from the global settings.  You can change at the global level or at the target level.
func (o AuditProfileOutput) IsPaidUsageEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.BoolOutput { return v.IsPaidUsageEnabled }).(pulumi.BoolOutput)
}

// Details about the current state of the audit profile in Data Safe.
func (o AuditProfileOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Indicates the number of months the audit records will be stored offline in the Data Safe audit archive. Minimum: 0; Maximum: 72 months. If you have a requirement to store the audit data even longer in archive, please contact the Oracle Support.
func (o AuditProfileOutput) OfflineMonths() pulumi.IntOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.IntOutput { return v.OfflineMonths }).(pulumi.IntOutput)
}

// Indicates the number of months the audit records will be stored online in Oracle Data Safe audit repository for immediate reporting and analysis.  Minimum: 1; Maximum:12 months
func (o AuditProfileOutput) OnlineMonths() pulumi.IntOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.IntOutput { return v.OnlineMonths }).(pulumi.IntOutput)
}

// The current state of the audit profile.
func (o AuditProfileOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o AuditProfileOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// The OCID of the Data Safe target for which the audit profile is created.
func (o AuditProfileOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.StringOutput { return v.TargetId }).(pulumi.StringOutput)
}

// The date and time the audit profile was created, in the format defined by RFC3339.
func (o AuditProfileOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the audit profile was updated, in the format defined by RFC3339.
func (o AuditProfileOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *AuditProfile) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type AuditProfileArrayOutput struct{ *pulumi.OutputState }

func (AuditProfileArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AuditProfile)(nil)).Elem()
}

func (o AuditProfileArrayOutput) ToAuditProfileArrayOutput() AuditProfileArrayOutput {
	return o
}

func (o AuditProfileArrayOutput) ToAuditProfileArrayOutputWithContext(ctx context.Context) AuditProfileArrayOutput {
	return o
}

func (o AuditProfileArrayOutput) Index(i pulumi.IntInput) AuditProfileOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *AuditProfile {
		return vs[0].([]*AuditProfile)[vs[1].(int)]
	}).(AuditProfileOutput)
}

type AuditProfileMapOutput struct{ *pulumi.OutputState }

func (AuditProfileMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AuditProfile)(nil)).Elem()
}

func (o AuditProfileMapOutput) ToAuditProfileMapOutput() AuditProfileMapOutput {
	return o
}

func (o AuditProfileMapOutput) ToAuditProfileMapOutputWithContext(ctx context.Context) AuditProfileMapOutput {
	return o
}

func (o AuditProfileMapOutput) MapIndex(k pulumi.StringInput) AuditProfileOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *AuditProfile {
		return vs[0].(map[string]*AuditProfile)[vs[1].(string)]
	}).(AuditProfileOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*AuditProfileInput)(nil)).Elem(), &AuditProfile{})
	pulumi.RegisterInputType(reflect.TypeOf((*AuditProfileArrayInput)(nil)).Elem(), AuditProfileArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*AuditProfileMapInput)(nil)).Elem(), AuditProfileMap{})
	pulumi.RegisterOutputType(AuditProfileOutput{})
	pulumi.RegisterOutputType(AuditProfileArrayOutput{})
	pulumi.RegisterOutputType(AuditProfileMapOutput{})
}