// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This resource provides the Security Policy Deployment resource in Oracle Cloud Infrastructure Data Safe service.
//
// Updates the security policy deployment.
//
// ## Import
//
// SecurityPolicyDeployments can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:DataSafe/securityPolicyDeployment:SecurityPolicyDeployment test_security_policy_deployment "id"
//
// ```
type SecurityPolicyDeployment struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the compartment containing the security policy deployment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) The description of the security policy deployment.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The display name of the security policy deployment. The name does not have to be unique, and it is changeable.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Details about the current state of the security policy deployment in Data Safe.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The OCID of the security policy deployment resource.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SecurityPolicyDeploymentId pulumi.StringOutput `pulumi:"securityPolicyDeploymentId"`
	// The OCID of the security policy corresponding to the security policy deployment.
	SecurityPolicyId pulumi.StringOutput `pulumi:"securityPolicyId"`
	// The current state of the security policy deployment.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The OCID of the target where the security policy is deployed.
	TargetId pulumi.StringOutput `pulumi:"targetId"`
	// The time that the security policy deployment was created, in the format defined by RFC3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The last date and time the security policy deployment was updated, in the format defined by RFC3339.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewSecurityPolicyDeployment registers a new resource with the given unique name, arguments, and options.
func NewSecurityPolicyDeployment(ctx *pulumi.Context,
	name string, args *SecurityPolicyDeploymentArgs, opts ...pulumi.ResourceOption) (*SecurityPolicyDeployment, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.SecurityPolicyDeploymentId == nil {
		return nil, errors.New("invalid value for required argument 'SecurityPolicyDeploymentId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource SecurityPolicyDeployment
	err := ctx.RegisterResource("oci:DataSafe/securityPolicyDeployment:SecurityPolicyDeployment", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSecurityPolicyDeployment gets an existing SecurityPolicyDeployment resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSecurityPolicyDeployment(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SecurityPolicyDeploymentState, opts ...pulumi.ResourceOption) (*SecurityPolicyDeployment, error) {
	var resource SecurityPolicyDeployment
	err := ctx.ReadResource("oci:DataSafe/securityPolicyDeployment:SecurityPolicyDeployment", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering SecurityPolicyDeployment resources.
type securityPolicyDeploymentState struct {
	// (Updatable) The OCID of the compartment containing the security policy deployment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the security policy deployment.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the security policy deployment. The name does not have to be unique, and it is changeable.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Details about the current state of the security policy deployment in Data Safe.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The OCID of the security policy deployment resource.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SecurityPolicyDeploymentId *string `pulumi:"securityPolicyDeploymentId"`
	// The OCID of the security policy corresponding to the security policy deployment.
	SecurityPolicyId *string `pulumi:"securityPolicyId"`
	// The current state of the security policy deployment.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The OCID of the target where the security policy is deployed.
	TargetId *string `pulumi:"targetId"`
	// The time that the security policy deployment was created, in the format defined by RFC3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The last date and time the security policy deployment was updated, in the format defined by RFC3339.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type SecurityPolicyDeploymentState struct {
	// (Updatable) The OCID of the compartment containing the security policy deployment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the security policy deployment.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the security policy deployment. The name does not have to be unique, and it is changeable.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Details about the current state of the security policy deployment in Data Safe.
	LifecycleDetails pulumi.StringPtrInput
	// The OCID of the security policy deployment resource.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SecurityPolicyDeploymentId pulumi.StringPtrInput
	// The OCID of the security policy corresponding to the security policy deployment.
	SecurityPolicyId pulumi.StringPtrInput
	// The current state of the security policy deployment.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The OCID of the target where the security policy is deployed.
	TargetId pulumi.StringPtrInput
	// The time that the security policy deployment was created, in the format defined by RFC3339.
	TimeCreated pulumi.StringPtrInput
	// The last date and time the security policy deployment was updated, in the format defined by RFC3339.
	TimeUpdated pulumi.StringPtrInput
}

func (SecurityPolicyDeploymentState) ElementType() reflect.Type {
	return reflect.TypeOf((*securityPolicyDeploymentState)(nil)).Elem()
}

type securityPolicyDeploymentArgs struct {
	// (Updatable) The OCID of the compartment containing the security policy deployment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) The description of the security policy deployment.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the security policy deployment. The name does not have to be unique, and it is changeable.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the security policy deployment resource.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SecurityPolicyDeploymentId string `pulumi:"securityPolicyDeploymentId"`
}

// The set of arguments for constructing a SecurityPolicyDeployment resource.
type SecurityPolicyDeploymentArgs struct {
	// (Updatable) The OCID of the compartment containing the security policy deployment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) The description of the security policy deployment.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the security policy deployment. The name does not have to be unique, and it is changeable.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The OCID of the security policy deployment resource.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SecurityPolicyDeploymentId pulumi.StringInput
}

func (SecurityPolicyDeploymentArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*securityPolicyDeploymentArgs)(nil)).Elem()
}

type SecurityPolicyDeploymentInput interface {
	pulumi.Input

	ToSecurityPolicyDeploymentOutput() SecurityPolicyDeploymentOutput
	ToSecurityPolicyDeploymentOutputWithContext(ctx context.Context) SecurityPolicyDeploymentOutput
}

func (*SecurityPolicyDeployment) ElementType() reflect.Type {
	return reflect.TypeOf((**SecurityPolicyDeployment)(nil)).Elem()
}

func (i *SecurityPolicyDeployment) ToSecurityPolicyDeploymentOutput() SecurityPolicyDeploymentOutput {
	return i.ToSecurityPolicyDeploymentOutputWithContext(context.Background())
}

func (i *SecurityPolicyDeployment) ToSecurityPolicyDeploymentOutputWithContext(ctx context.Context) SecurityPolicyDeploymentOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SecurityPolicyDeploymentOutput)
}

func (i *SecurityPolicyDeployment) ToOutput(ctx context.Context) pulumix.Output[*SecurityPolicyDeployment] {
	return pulumix.Output[*SecurityPolicyDeployment]{
		OutputState: i.ToSecurityPolicyDeploymentOutputWithContext(ctx).OutputState,
	}
}

// SecurityPolicyDeploymentArrayInput is an input type that accepts SecurityPolicyDeploymentArray and SecurityPolicyDeploymentArrayOutput values.
// You can construct a concrete instance of `SecurityPolicyDeploymentArrayInput` via:
//
//	SecurityPolicyDeploymentArray{ SecurityPolicyDeploymentArgs{...} }
type SecurityPolicyDeploymentArrayInput interface {
	pulumi.Input

	ToSecurityPolicyDeploymentArrayOutput() SecurityPolicyDeploymentArrayOutput
	ToSecurityPolicyDeploymentArrayOutputWithContext(context.Context) SecurityPolicyDeploymentArrayOutput
}

type SecurityPolicyDeploymentArray []SecurityPolicyDeploymentInput

func (SecurityPolicyDeploymentArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SecurityPolicyDeployment)(nil)).Elem()
}

func (i SecurityPolicyDeploymentArray) ToSecurityPolicyDeploymentArrayOutput() SecurityPolicyDeploymentArrayOutput {
	return i.ToSecurityPolicyDeploymentArrayOutputWithContext(context.Background())
}

func (i SecurityPolicyDeploymentArray) ToSecurityPolicyDeploymentArrayOutputWithContext(ctx context.Context) SecurityPolicyDeploymentArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SecurityPolicyDeploymentArrayOutput)
}

func (i SecurityPolicyDeploymentArray) ToOutput(ctx context.Context) pulumix.Output[[]*SecurityPolicyDeployment] {
	return pulumix.Output[[]*SecurityPolicyDeployment]{
		OutputState: i.ToSecurityPolicyDeploymentArrayOutputWithContext(ctx).OutputState,
	}
}

// SecurityPolicyDeploymentMapInput is an input type that accepts SecurityPolicyDeploymentMap and SecurityPolicyDeploymentMapOutput values.
// You can construct a concrete instance of `SecurityPolicyDeploymentMapInput` via:
//
//	SecurityPolicyDeploymentMap{ "key": SecurityPolicyDeploymentArgs{...} }
type SecurityPolicyDeploymentMapInput interface {
	pulumi.Input

	ToSecurityPolicyDeploymentMapOutput() SecurityPolicyDeploymentMapOutput
	ToSecurityPolicyDeploymentMapOutputWithContext(context.Context) SecurityPolicyDeploymentMapOutput
}

type SecurityPolicyDeploymentMap map[string]SecurityPolicyDeploymentInput

func (SecurityPolicyDeploymentMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SecurityPolicyDeployment)(nil)).Elem()
}

func (i SecurityPolicyDeploymentMap) ToSecurityPolicyDeploymentMapOutput() SecurityPolicyDeploymentMapOutput {
	return i.ToSecurityPolicyDeploymentMapOutputWithContext(context.Background())
}

func (i SecurityPolicyDeploymentMap) ToSecurityPolicyDeploymentMapOutputWithContext(ctx context.Context) SecurityPolicyDeploymentMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SecurityPolicyDeploymentMapOutput)
}

func (i SecurityPolicyDeploymentMap) ToOutput(ctx context.Context) pulumix.Output[map[string]*SecurityPolicyDeployment] {
	return pulumix.Output[map[string]*SecurityPolicyDeployment]{
		OutputState: i.ToSecurityPolicyDeploymentMapOutputWithContext(ctx).OutputState,
	}
}

type SecurityPolicyDeploymentOutput struct{ *pulumi.OutputState }

func (SecurityPolicyDeploymentOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**SecurityPolicyDeployment)(nil)).Elem()
}

func (o SecurityPolicyDeploymentOutput) ToSecurityPolicyDeploymentOutput() SecurityPolicyDeploymentOutput {
	return o
}

func (o SecurityPolicyDeploymentOutput) ToSecurityPolicyDeploymentOutputWithContext(ctx context.Context) SecurityPolicyDeploymentOutput {
	return o
}

func (o SecurityPolicyDeploymentOutput) ToOutput(ctx context.Context) pulumix.Output[*SecurityPolicyDeployment] {
	return pulumix.Output[*SecurityPolicyDeployment]{
		OutputState: o.OutputState,
	}
}

// (Updatable) The OCID of the compartment containing the security policy deployment.
func (o SecurityPolicyDeploymentOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
func (o SecurityPolicyDeploymentOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) The description of the security policy deployment.
func (o SecurityPolicyDeploymentOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) The display name of the security policy deployment. The name does not have to be unique, and it is changeable.
func (o SecurityPolicyDeploymentOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o SecurityPolicyDeploymentOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// Details about the current state of the security policy deployment in Data Safe.
func (o SecurityPolicyDeploymentOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The OCID of the security policy deployment resource.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o SecurityPolicyDeploymentOutput) SecurityPolicyDeploymentId() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.StringOutput { return v.SecurityPolicyDeploymentId }).(pulumi.StringOutput)
}

// The OCID of the security policy corresponding to the security policy deployment.
func (o SecurityPolicyDeploymentOutput) SecurityPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.StringOutput { return v.SecurityPolicyId }).(pulumi.StringOutput)
}

// The current state of the security policy deployment.
func (o SecurityPolicyDeploymentOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o SecurityPolicyDeploymentOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// The OCID of the target where the security policy is deployed.
func (o SecurityPolicyDeploymentOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.StringOutput { return v.TargetId }).(pulumi.StringOutput)
}

// The time that the security policy deployment was created, in the format defined by RFC3339.
func (o SecurityPolicyDeploymentOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The last date and time the security policy deployment was updated, in the format defined by RFC3339.
func (o SecurityPolicyDeploymentOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *SecurityPolicyDeployment) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type SecurityPolicyDeploymentArrayOutput struct{ *pulumi.OutputState }

func (SecurityPolicyDeploymentArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SecurityPolicyDeployment)(nil)).Elem()
}

func (o SecurityPolicyDeploymentArrayOutput) ToSecurityPolicyDeploymentArrayOutput() SecurityPolicyDeploymentArrayOutput {
	return o
}

func (o SecurityPolicyDeploymentArrayOutput) ToSecurityPolicyDeploymentArrayOutputWithContext(ctx context.Context) SecurityPolicyDeploymentArrayOutput {
	return o
}

func (o SecurityPolicyDeploymentArrayOutput) ToOutput(ctx context.Context) pulumix.Output[[]*SecurityPolicyDeployment] {
	return pulumix.Output[[]*SecurityPolicyDeployment]{
		OutputState: o.OutputState,
	}
}

func (o SecurityPolicyDeploymentArrayOutput) Index(i pulumi.IntInput) SecurityPolicyDeploymentOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *SecurityPolicyDeployment {
		return vs[0].([]*SecurityPolicyDeployment)[vs[1].(int)]
	}).(SecurityPolicyDeploymentOutput)
}

type SecurityPolicyDeploymentMapOutput struct{ *pulumi.OutputState }

func (SecurityPolicyDeploymentMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SecurityPolicyDeployment)(nil)).Elem()
}

func (o SecurityPolicyDeploymentMapOutput) ToSecurityPolicyDeploymentMapOutput() SecurityPolicyDeploymentMapOutput {
	return o
}

func (o SecurityPolicyDeploymentMapOutput) ToSecurityPolicyDeploymentMapOutputWithContext(ctx context.Context) SecurityPolicyDeploymentMapOutput {
	return o
}

func (o SecurityPolicyDeploymentMapOutput) ToOutput(ctx context.Context) pulumix.Output[map[string]*SecurityPolicyDeployment] {
	return pulumix.Output[map[string]*SecurityPolicyDeployment]{
		OutputState: o.OutputState,
	}
}

func (o SecurityPolicyDeploymentMapOutput) MapIndex(k pulumi.StringInput) SecurityPolicyDeploymentOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *SecurityPolicyDeployment {
		return vs[0].(map[string]*SecurityPolicyDeployment)[vs[1].(string)]
	}).(SecurityPolicyDeploymentOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*SecurityPolicyDeploymentInput)(nil)).Elem(), &SecurityPolicyDeployment{})
	pulumi.RegisterInputType(reflect.TypeOf((*SecurityPolicyDeploymentArrayInput)(nil)).Elem(), SecurityPolicyDeploymentArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*SecurityPolicyDeploymentMapInput)(nil)).Elem(), SecurityPolicyDeploymentMap{})
	pulumi.RegisterOutputType(SecurityPolicyDeploymentOutput{})
	pulumi.RegisterOutputType(SecurityPolicyDeploymentArrayOutput{})
	pulumi.RegisterOutputType(SecurityPolicyDeploymentMapOutput{})
}