// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package fusionapps

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Fusion Environment Admin User resource in Oracle Cloud Infrastructure Fusion Apps service.
//
// # Create a FusionEnvironment admin user
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/FusionApps"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := FusionApps.NewFusionEnvironmentAdminUser(ctx, "testFusionEnvironmentAdminUser", &FusionApps.FusionEnvironmentAdminUserArgs{
//				EmailAddress:        pulumi.Any(_var.Fusion_environment_admin_user_email_address),
//				FirstName:           pulumi.Any(_var.Fusion_environment_admin_user_first_name),
//				FusionEnvironmentId: pulumi.Any(oci_fusion_apps_fusion_environment.Test_fusion_environment.Id),
//				LastName:            pulumi.Any(_var.Fusion_environment_admin_user_last_name),
//				Password:            pulumi.Any(_var.Fusion_environment_admin_user_password),
//				Username:            pulumi.Any(_var.Fusion_environment_admin_user_username),
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
// FusionEnvironmentAdminUsers can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:FusionApps/fusionEnvironmentAdminUser:FusionEnvironmentAdminUser test_fusion_environment_admin_user "fusionEnvironments/{fusionEnvironmentId}/adminUsers/{adminUsername}"
//
// ```
type FusionEnvironmentAdminUser struct {
	pulumi.CustomResourceState

	// The email address for the administrator.
	EmailAddress pulumi.StringOutput `pulumi:"emailAddress"`
	// The administrator's first name.
	FirstName pulumi.StringOutput `pulumi:"firstName"`
	// unique FusionEnvironment identifier
	FusionEnvironmentId pulumi.StringOutput `pulumi:"fusionEnvironmentId"`
	// A page of AdminUserSummary objects.
	Items FusionEnvironmentAdminUserItemArrayOutput `pulumi:"items"`
	// The administrator's last name.
	LastName pulumi.StringOutput `pulumi:"lastName"`
	// The password for the administrator.
	Password pulumi.StringOutput `pulumi:"password"`
	// The username for the administrator.
	Username pulumi.StringOutput `pulumi:"username"`
}

// NewFusionEnvironmentAdminUser registers a new resource with the given unique name, arguments, and options.
func NewFusionEnvironmentAdminUser(ctx *pulumi.Context,
	name string, args *FusionEnvironmentAdminUserArgs, opts ...pulumi.ResourceOption) (*FusionEnvironmentAdminUser, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.EmailAddress == nil {
		return nil, errors.New("invalid value for required argument 'EmailAddress'")
	}
	if args.FirstName == nil {
		return nil, errors.New("invalid value for required argument 'FirstName'")
	}
	if args.FusionEnvironmentId == nil {
		return nil, errors.New("invalid value for required argument 'FusionEnvironmentId'")
	}
	if args.LastName == nil {
		return nil, errors.New("invalid value for required argument 'LastName'")
	}
	if args.Password == nil {
		return nil, errors.New("invalid value for required argument 'Password'")
	}
	if args.Username == nil {
		return nil, errors.New("invalid value for required argument 'Username'")
	}
	var resource FusionEnvironmentAdminUser
	err := ctx.RegisterResource("oci:FusionApps/fusionEnvironmentAdminUser:FusionEnvironmentAdminUser", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetFusionEnvironmentAdminUser gets an existing FusionEnvironmentAdminUser resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetFusionEnvironmentAdminUser(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *FusionEnvironmentAdminUserState, opts ...pulumi.ResourceOption) (*FusionEnvironmentAdminUser, error) {
	var resource FusionEnvironmentAdminUser
	err := ctx.ReadResource("oci:FusionApps/fusionEnvironmentAdminUser:FusionEnvironmentAdminUser", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering FusionEnvironmentAdminUser resources.
type fusionEnvironmentAdminUserState struct {
	// The email address for the administrator.
	EmailAddress *string `pulumi:"emailAddress"`
	// The administrator's first name.
	FirstName *string `pulumi:"firstName"`
	// unique FusionEnvironment identifier
	FusionEnvironmentId *string `pulumi:"fusionEnvironmentId"`
	// A page of AdminUserSummary objects.
	Items []FusionEnvironmentAdminUserItem `pulumi:"items"`
	// The administrator's last name.
	LastName *string `pulumi:"lastName"`
	// The password for the administrator.
	Password *string `pulumi:"password"`
	// The username for the administrator.
	Username *string `pulumi:"username"`
}

type FusionEnvironmentAdminUserState struct {
	// The email address for the administrator.
	EmailAddress pulumi.StringPtrInput
	// The administrator's first name.
	FirstName pulumi.StringPtrInput
	// unique FusionEnvironment identifier
	FusionEnvironmentId pulumi.StringPtrInput
	// A page of AdminUserSummary objects.
	Items FusionEnvironmentAdminUserItemArrayInput
	// The administrator's last name.
	LastName pulumi.StringPtrInput
	// The password for the administrator.
	Password pulumi.StringPtrInput
	// The username for the administrator.
	Username pulumi.StringPtrInput
}

func (FusionEnvironmentAdminUserState) ElementType() reflect.Type {
	return reflect.TypeOf((*fusionEnvironmentAdminUserState)(nil)).Elem()
}

type fusionEnvironmentAdminUserArgs struct {
	// The email address for the administrator.
	EmailAddress string `pulumi:"emailAddress"`
	// The administrator's first name.
	FirstName string `pulumi:"firstName"`
	// unique FusionEnvironment identifier
	FusionEnvironmentId string `pulumi:"fusionEnvironmentId"`
	// The administrator's last name.
	LastName string `pulumi:"lastName"`
	// The password for the administrator.
	Password string `pulumi:"password"`
	// The username for the administrator.
	Username string `pulumi:"username"`
}

// The set of arguments for constructing a FusionEnvironmentAdminUser resource.
type FusionEnvironmentAdminUserArgs struct {
	// The email address for the administrator.
	EmailAddress pulumi.StringInput
	// The administrator's first name.
	FirstName pulumi.StringInput
	// unique FusionEnvironment identifier
	FusionEnvironmentId pulumi.StringInput
	// The administrator's last name.
	LastName pulumi.StringInput
	// The password for the administrator.
	Password pulumi.StringInput
	// The username for the administrator.
	Username pulumi.StringInput
}

func (FusionEnvironmentAdminUserArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*fusionEnvironmentAdminUserArgs)(nil)).Elem()
}

type FusionEnvironmentAdminUserInput interface {
	pulumi.Input

	ToFusionEnvironmentAdminUserOutput() FusionEnvironmentAdminUserOutput
	ToFusionEnvironmentAdminUserOutputWithContext(ctx context.Context) FusionEnvironmentAdminUserOutput
}

func (*FusionEnvironmentAdminUser) ElementType() reflect.Type {
	return reflect.TypeOf((**FusionEnvironmentAdminUser)(nil)).Elem()
}

func (i *FusionEnvironmentAdminUser) ToFusionEnvironmentAdminUserOutput() FusionEnvironmentAdminUserOutput {
	return i.ToFusionEnvironmentAdminUserOutputWithContext(context.Background())
}

func (i *FusionEnvironmentAdminUser) ToFusionEnvironmentAdminUserOutputWithContext(ctx context.Context) FusionEnvironmentAdminUserOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FusionEnvironmentAdminUserOutput)
}

// FusionEnvironmentAdminUserArrayInput is an input type that accepts FusionEnvironmentAdminUserArray and FusionEnvironmentAdminUserArrayOutput values.
// You can construct a concrete instance of `FusionEnvironmentAdminUserArrayInput` via:
//
//	FusionEnvironmentAdminUserArray{ FusionEnvironmentAdminUserArgs{...} }
type FusionEnvironmentAdminUserArrayInput interface {
	pulumi.Input

	ToFusionEnvironmentAdminUserArrayOutput() FusionEnvironmentAdminUserArrayOutput
	ToFusionEnvironmentAdminUserArrayOutputWithContext(context.Context) FusionEnvironmentAdminUserArrayOutput
}

type FusionEnvironmentAdminUserArray []FusionEnvironmentAdminUserInput

func (FusionEnvironmentAdminUserArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*FusionEnvironmentAdminUser)(nil)).Elem()
}

func (i FusionEnvironmentAdminUserArray) ToFusionEnvironmentAdminUserArrayOutput() FusionEnvironmentAdminUserArrayOutput {
	return i.ToFusionEnvironmentAdminUserArrayOutputWithContext(context.Background())
}

func (i FusionEnvironmentAdminUserArray) ToFusionEnvironmentAdminUserArrayOutputWithContext(ctx context.Context) FusionEnvironmentAdminUserArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FusionEnvironmentAdminUserArrayOutput)
}

// FusionEnvironmentAdminUserMapInput is an input type that accepts FusionEnvironmentAdminUserMap and FusionEnvironmentAdminUserMapOutput values.
// You can construct a concrete instance of `FusionEnvironmentAdminUserMapInput` via:
//
//	FusionEnvironmentAdminUserMap{ "key": FusionEnvironmentAdminUserArgs{...} }
type FusionEnvironmentAdminUserMapInput interface {
	pulumi.Input

	ToFusionEnvironmentAdminUserMapOutput() FusionEnvironmentAdminUserMapOutput
	ToFusionEnvironmentAdminUserMapOutputWithContext(context.Context) FusionEnvironmentAdminUserMapOutput
}

type FusionEnvironmentAdminUserMap map[string]FusionEnvironmentAdminUserInput

func (FusionEnvironmentAdminUserMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*FusionEnvironmentAdminUser)(nil)).Elem()
}

func (i FusionEnvironmentAdminUserMap) ToFusionEnvironmentAdminUserMapOutput() FusionEnvironmentAdminUserMapOutput {
	return i.ToFusionEnvironmentAdminUserMapOutputWithContext(context.Background())
}

func (i FusionEnvironmentAdminUserMap) ToFusionEnvironmentAdminUserMapOutputWithContext(ctx context.Context) FusionEnvironmentAdminUserMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FusionEnvironmentAdminUserMapOutput)
}

type FusionEnvironmentAdminUserOutput struct{ *pulumi.OutputState }

func (FusionEnvironmentAdminUserOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**FusionEnvironmentAdminUser)(nil)).Elem()
}

func (o FusionEnvironmentAdminUserOutput) ToFusionEnvironmentAdminUserOutput() FusionEnvironmentAdminUserOutput {
	return o
}

func (o FusionEnvironmentAdminUserOutput) ToFusionEnvironmentAdminUserOutputWithContext(ctx context.Context) FusionEnvironmentAdminUserOutput {
	return o
}

// The email address for the administrator.
func (o FusionEnvironmentAdminUserOutput) EmailAddress() pulumi.StringOutput {
	return o.ApplyT(func(v *FusionEnvironmentAdminUser) pulumi.StringOutput { return v.EmailAddress }).(pulumi.StringOutput)
}

// The administrator's first name.
func (o FusionEnvironmentAdminUserOutput) FirstName() pulumi.StringOutput {
	return o.ApplyT(func(v *FusionEnvironmentAdminUser) pulumi.StringOutput { return v.FirstName }).(pulumi.StringOutput)
}

// unique FusionEnvironment identifier
func (o FusionEnvironmentAdminUserOutput) FusionEnvironmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *FusionEnvironmentAdminUser) pulumi.StringOutput { return v.FusionEnvironmentId }).(pulumi.StringOutput)
}

// A page of AdminUserSummary objects.
func (o FusionEnvironmentAdminUserOutput) Items() FusionEnvironmentAdminUserItemArrayOutput {
	return o.ApplyT(func(v *FusionEnvironmentAdminUser) FusionEnvironmentAdminUserItemArrayOutput { return v.Items }).(FusionEnvironmentAdminUserItemArrayOutput)
}

// The administrator's last name.
func (o FusionEnvironmentAdminUserOutput) LastName() pulumi.StringOutput {
	return o.ApplyT(func(v *FusionEnvironmentAdminUser) pulumi.StringOutput { return v.LastName }).(pulumi.StringOutput)
}

// The password for the administrator.
func (o FusionEnvironmentAdminUserOutput) Password() pulumi.StringOutput {
	return o.ApplyT(func(v *FusionEnvironmentAdminUser) pulumi.StringOutput { return v.Password }).(pulumi.StringOutput)
}

// The username for the administrator.
func (o FusionEnvironmentAdminUserOutput) Username() pulumi.StringOutput {
	return o.ApplyT(func(v *FusionEnvironmentAdminUser) pulumi.StringOutput { return v.Username }).(pulumi.StringOutput)
}

type FusionEnvironmentAdminUserArrayOutput struct{ *pulumi.OutputState }

func (FusionEnvironmentAdminUserArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*FusionEnvironmentAdminUser)(nil)).Elem()
}

func (o FusionEnvironmentAdminUserArrayOutput) ToFusionEnvironmentAdminUserArrayOutput() FusionEnvironmentAdminUserArrayOutput {
	return o
}

func (o FusionEnvironmentAdminUserArrayOutput) ToFusionEnvironmentAdminUserArrayOutputWithContext(ctx context.Context) FusionEnvironmentAdminUserArrayOutput {
	return o
}

func (o FusionEnvironmentAdminUserArrayOutput) Index(i pulumi.IntInput) FusionEnvironmentAdminUserOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *FusionEnvironmentAdminUser {
		return vs[0].([]*FusionEnvironmentAdminUser)[vs[1].(int)]
	}).(FusionEnvironmentAdminUserOutput)
}

type FusionEnvironmentAdminUserMapOutput struct{ *pulumi.OutputState }

func (FusionEnvironmentAdminUserMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*FusionEnvironmentAdminUser)(nil)).Elem()
}

func (o FusionEnvironmentAdminUserMapOutput) ToFusionEnvironmentAdminUserMapOutput() FusionEnvironmentAdminUserMapOutput {
	return o
}

func (o FusionEnvironmentAdminUserMapOutput) ToFusionEnvironmentAdminUserMapOutputWithContext(ctx context.Context) FusionEnvironmentAdminUserMapOutput {
	return o
}

func (o FusionEnvironmentAdminUserMapOutput) MapIndex(k pulumi.StringInput) FusionEnvironmentAdminUserOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *FusionEnvironmentAdminUser {
		return vs[0].(map[string]*FusionEnvironmentAdminUser)[vs[1].(string)]
	}).(FusionEnvironmentAdminUserOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*FusionEnvironmentAdminUserInput)(nil)).Elem(), &FusionEnvironmentAdminUser{})
	pulumi.RegisterInputType(reflect.TypeOf((*FusionEnvironmentAdminUserArrayInput)(nil)).Elem(), FusionEnvironmentAdminUserArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*FusionEnvironmentAdminUserMapInput)(nil)).Elem(), FusionEnvironmentAdminUserMap{})
	pulumi.RegisterOutputType(FusionEnvironmentAdminUserOutput{})
	pulumi.RegisterOutputType(FusionEnvironmentAdminUserArrayOutput{})
	pulumi.RegisterOutputType(FusionEnvironmentAdminUserMapOutput{})
}