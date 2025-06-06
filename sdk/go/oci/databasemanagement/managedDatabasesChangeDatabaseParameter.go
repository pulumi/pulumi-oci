// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Managed Databases Change Database Parameter resource in Oracle Cloud Infrastructure Database Management service.
//
// Changes database parameter values. There are two kinds of database
// parameters:
//
//   - Dynamic parameters: They can be changed for the current Oracle
//     Database instance. The changes take effect immediately.
//   - Static parameters: They cannot be changed for the current instance.
//     You must change these parameters and then restart the database before
//     changes take effect.
//
// **Note:** If the instance is started using a text initialization
// parameter file, the parameter changes are applicable only for the
// current instance. You must update them manually to be passed to
// a future instance.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/databasemanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := databasemanagement.NewManagedDatabasesChangeDatabaseParameter(ctx, "test_managed_databases_change_database_parameter", &databasemanagement.ManagedDatabasesChangeDatabaseParameterArgs{
//				ManagedDatabaseId: pulumi.Any(testManagedDatabase.Id),
//				Parameters: databasemanagement.ManagedDatabasesChangeDatabaseParameterParameterArray{
//					&databasemanagement.ManagedDatabasesChangeDatabaseParameterParameterArgs{
//						Name:          pulumi.Any(managedDatabasesChangeDatabaseParameterParametersName),
//						Value:         pulumi.Any(managedDatabasesChangeDatabaseParameterParametersValue),
//						UpdateComment: pulumi.Any(managedDatabasesChangeDatabaseParameterParametersUpdateComment),
//					},
//				},
//				Scope: pulumi.Any(managedDatabasesChangeDatabaseParameterScope),
//				Credentials: &databasemanagement.ManagedDatabasesChangeDatabaseParameterCredentialsArgs{
//					Password: pulumi.Any(managedDatabasesChangeDatabaseParameterCredentialsPassword),
//					Role:     pulumi.Any(managedDatabasesChangeDatabaseParameterCredentialsRole),
//					SecretId: pulumi.Any(testSecret.Id),
//					UserName: pulumi.Any(testUser.Name),
//				},
//				DatabaseCredential: &databasemanagement.ManagedDatabasesChangeDatabaseParameterDatabaseCredentialArgs{
//					CredentialType:    pulumi.Any(managedDatabasesChangeDatabaseParameterDatabaseCredentialCredentialType),
//					NamedCredentialId: pulumi.Any(testNamedCredential.Id),
//					Password:          pulumi.Any(managedDatabasesChangeDatabaseParameterDatabaseCredentialPassword),
//					PasswordSecretId:  pulumi.Any(testSecret.Id),
//					Role:              pulumi.Any(managedDatabasesChangeDatabaseParameterDatabaseCredentialRole),
//					Username:          pulumi.Any(managedDatabasesChangeDatabaseParameterDatabaseCredentialUsername),
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
// Import is not supported for this resource.
type ManagedDatabasesChangeDatabaseParameter struct {
	pulumi.CustomResourceState

	// The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
	Credentials ManagedDatabasesChangeDatabaseParameterCredentialsOutput `pulumi:"credentials"`
	// The credential to connect to the database to perform tablespace administration tasks.
	DatabaseCredential ManagedDatabasesChangeDatabaseParameterDatabaseCredentialOutput `pulumi:"databaseCredential"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId pulumi.StringOutput `pulumi:"managedDatabaseId"`
	// A list of database parameters and their values.
	Parameters ManagedDatabasesChangeDatabaseParameterParameterArrayOutput `pulumi:"parameters"`
	// The clause used to specify when the parameter change takes effect.
	//
	// Use `MEMORY` to make the change in memory and affect it immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Scope pulumi.StringOutput `pulumi:"scope"`
}

// NewManagedDatabasesChangeDatabaseParameter registers a new resource with the given unique name, arguments, and options.
func NewManagedDatabasesChangeDatabaseParameter(ctx *pulumi.Context,
	name string, args *ManagedDatabasesChangeDatabaseParameterArgs, opts ...pulumi.ResourceOption) (*ManagedDatabasesChangeDatabaseParameter, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ManagedDatabaseId == nil {
		return nil, errors.New("invalid value for required argument 'ManagedDatabaseId'")
	}
	if args.Parameters == nil {
		return nil, errors.New("invalid value for required argument 'Parameters'")
	}
	if args.Scope == nil {
		return nil, errors.New("invalid value for required argument 'Scope'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ManagedDatabasesChangeDatabaseParameter
	err := ctx.RegisterResource("oci:DatabaseManagement/managedDatabasesChangeDatabaseParameter:ManagedDatabasesChangeDatabaseParameter", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetManagedDatabasesChangeDatabaseParameter gets an existing ManagedDatabasesChangeDatabaseParameter resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetManagedDatabasesChangeDatabaseParameter(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ManagedDatabasesChangeDatabaseParameterState, opts ...pulumi.ResourceOption) (*ManagedDatabasesChangeDatabaseParameter, error) {
	var resource ManagedDatabasesChangeDatabaseParameter
	err := ctx.ReadResource("oci:DatabaseManagement/managedDatabasesChangeDatabaseParameter:ManagedDatabasesChangeDatabaseParameter", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ManagedDatabasesChangeDatabaseParameter resources.
type managedDatabasesChangeDatabaseParameterState struct {
	// The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
	Credentials *ManagedDatabasesChangeDatabaseParameterCredentials `pulumi:"credentials"`
	// The credential to connect to the database to perform tablespace administration tasks.
	DatabaseCredential *ManagedDatabasesChangeDatabaseParameterDatabaseCredential `pulumi:"databaseCredential"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId *string `pulumi:"managedDatabaseId"`
	// A list of database parameters and their values.
	Parameters []ManagedDatabasesChangeDatabaseParameterParameter `pulumi:"parameters"`
	// The clause used to specify when the parameter change takes effect.
	//
	// Use `MEMORY` to make the change in memory and affect it immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Scope *string `pulumi:"scope"`
}

type ManagedDatabasesChangeDatabaseParameterState struct {
	// The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
	Credentials ManagedDatabasesChangeDatabaseParameterCredentialsPtrInput
	// The credential to connect to the database to perform tablespace administration tasks.
	DatabaseCredential ManagedDatabasesChangeDatabaseParameterDatabaseCredentialPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId pulumi.StringPtrInput
	// A list of database parameters and their values.
	Parameters ManagedDatabasesChangeDatabaseParameterParameterArrayInput
	// The clause used to specify when the parameter change takes effect.
	//
	// Use `MEMORY` to make the change in memory and affect it immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Scope pulumi.StringPtrInput
}

func (ManagedDatabasesChangeDatabaseParameterState) ElementType() reflect.Type {
	return reflect.TypeOf((*managedDatabasesChangeDatabaseParameterState)(nil)).Elem()
}

type managedDatabasesChangeDatabaseParameterArgs struct {
	// The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
	Credentials *ManagedDatabasesChangeDatabaseParameterCredentials `pulumi:"credentials"`
	// The credential to connect to the database to perform tablespace administration tasks.
	DatabaseCredential *ManagedDatabasesChangeDatabaseParameterDatabaseCredential `pulumi:"databaseCredential"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
	// A list of database parameters and their values.
	Parameters []ManagedDatabasesChangeDatabaseParameterParameter `pulumi:"parameters"`
	// The clause used to specify when the parameter change takes effect.
	//
	// Use `MEMORY` to make the change in memory and affect it immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Scope string `pulumi:"scope"`
}

// The set of arguments for constructing a ManagedDatabasesChangeDatabaseParameter resource.
type ManagedDatabasesChangeDatabaseParameterArgs struct {
	// The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
	Credentials ManagedDatabasesChangeDatabaseParameterCredentialsPtrInput
	// The credential to connect to the database to perform tablespace administration tasks.
	DatabaseCredential ManagedDatabasesChangeDatabaseParameterDatabaseCredentialPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId pulumi.StringInput
	// A list of database parameters and their values.
	Parameters ManagedDatabasesChangeDatabaseParameterParameterArrayInput
	// The clause used to specify when the parameter change takes effect.
	//
	// Use `MEMORY` to make the change in memory and affect it immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Scope pulumi.StringInput
}

func (ManagedDatabasesChangeDatabaseParameterArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*managedDatabasesChangeDatabaseParameterArgs)(nil)).Elem()
}

type ManagedDatabasesChangeDatabaseParameterInput interface {
	pulumi.Input

	ToManagedDatabasesChangeDatabaseParameterOutput() ManagedDatabasesChangeDatabaseParameterOutput
	ToManagedDatabasesChangeDatabaseParameterOutputWithContext(ctx context.Context) ManagedDatabasesChangeDatabaseParameterOutput
}

func (*ManagedDatabasesChangeDatabaseParameter) ElementType() reflect.Type {
	return reflect.TypeOf((**ManagedDatabasesChangeDatabaseParameter)(nil)).Elem()
}

func (i *ManagedDatabasesChangeDatabaseParameter) ToManagedDatabasesChangeDatabaseParameterOutput() ManagedDatabasesChangeDatabaseParameterOutput {
	return i.ToManagedDatabasesChangeDatabaseParameterOutputWithContext(context.Background())
}

func (i *ManagedDatabasesChangeDatabaseParameter) ToManagedDatabasesChangeDatabaseParameterOutputWithContext(ctx context.Context) ManagedDatabasesChangeDatabaseParameterOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedDatabasesChangeDatabaseParameterOutput)
}

// ManagedDatabasesChangeDatabaseParameterArrayInput is an input type that accepts ManagedDatabasesChangeDatabaseParameterArray and ManagedDatabasesChangeDatabaseParameterArrayOutput values.
// You can construct a concrete instance of `ManagedDatabasesChangeDatabaseParameterArrayInput` via:
//
//	ManagedDatabasesChangeDatabaseParameterArray{ ManagedDatabasesChangeDatabaseParameterArgs{...} }
type ManagedDatabasesChangeDatabaseParameterArrayInput interface {
	pulumi.Input

	ToManagedDatabasesChangeDatabaseParameterArrayOutput() ManagedDatabasesChangeDatabaseParameterArrayOutput
	ToManagedDatabasesChangeDatabaseParameterArrayOutputWithContext(context.Context) ManagedDatabasesChangeDatabaseParameterArrayOutput
}

type ManagedDatabasesChangeDatabaseParameterArray []ManagedDatabasesChangeDatabaseParameterInput

func (ManagedDatabasesChangeDatabaseParameterArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ManagedDatabasesChangeDatabaseParameter)(nil)).Elem()
}

func (i ManagedDatabasesChangeDatabaseParameterArray) ToManagedDatabasesChangeDatabaseParameterArrayOutput() ManagedDatabasesChangeDatabaseParameterArrayOutput {
	return i.ToManagedDatabasesChangeDatabaseParameterArrayOutputWithContext(context.Background())
}

func (i ManagedDatabasesChangeDatabaseParameterArray) ToManagedDatabasesChangeDatabaseParameterArrayOutputWithContext(ctx context.Context) ManagedDatabasesChangeDatabaseParameterArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedDatabasesChangeDatabaseParameterArrayOutput)
}

// ManagedDatabasesChangeDatabaseParameterMapInput is an input type that accepts ManagedDatabasesChangeDatabaseParameterMap and ManagedDatabasesChangeDatabaseParameterMapOutput values.
// You can construct a concrete instance of `ManagedDatabasesChangeDatabaseParameterMapInput` via:
//
//	ManagedDatabasesChangeDatabaseParameterMap{ "key": ManagedDatabasesChangeDatabaseParameterArgs{...} }
type ManagedDatabasesChangeDatabaseParameterMapInput interface {
	pulumi.Input

	ToManagedDatabasesChangeDatabaseParameterMapOutput() ManagedDatabasesChangeDatabaseParameterMapOutput
	ToManagedDatabasesChangeDatabaseParameterMapOutputWithContext(context.Context) ManagedDatabasesChangeDatabaseParameterMapOutput
}

type ManagedDatabasesChangeDatabaseParameterMap map[string]ManagedDatabasesChangeDatabaseParameterInput

func (ManagedDatabasesChangeDatabaseParameterMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ManagedDatabasesChangeDatabaseParameter)(nil)).Elem()
}

func (i ManagedDatabasesChangeDatabaseParameterMap) ToManagedDatabasesChangeDatabaseParameterMapOutput() ManagedDatabasesChangeDatabaseParameterMapOutput {
	return i.ToManagedDatabasesChangeDatabaseParameterMapOutputWithContext(context.Background())
}

func (i ManagedDatabasesChangeDatabaseParameterMap) ToManagedDatabasesChangeDatabaseParameterMapOutputWithContext(ctx context.Context) ManagedDatabasesChangeDatabaseParameterMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedDatabasesChangeDatabaseParameterMapOutput)
}

type ManagedDatabasesChangeDatabaseParameterOutput struct{ *pulumi.OutputState }

func (ManagedDatabasesChangeDatabaseParameterOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ManagedDatabasesChangeDatabaseParameter)(nil)).Elem()
}

func (o ManagedDatabasesChangeDatabaseParameterOutput) ToManagedDatabasesChangeDatabaseParameterOutput() ManagedDatabasesChangeDatabaseParameterOutput {
	return o
}

func (o ManagedDatabasesChangeDatabaseParameterOutput) ToManagedDatabasesChangeDatabaseParameterOutputWithContext(ctx context.Context) ManagedDatabasesChangeDatabaseParameterOutput {
	return o
}

// The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
func (o ManagedDatabasesChangeDatabaseParameterOutput) Credentials() ManagedDatabasesChangeDatabaseParameterCredentialsOutput {
	return o.ApplyT(func(v *ManagedDatabasesChangeDatabaseParameter) ManagedDatabasesChangeDatabaseParameterCredentialsOutput {
		return v.Credentials
	}).(ManagedDatabasesChangeDatabaseParameterCredentialsOutput)
}

// The credential to connect to the database to perform tablespace administration tasks.
func (o ManagedDatabasesChangeDatabaseParameterOutput) DatabaseCredential() ManagedDatabasesChangeDatabaseParameterDatabaseCredentialOutput {
	return o.ApplyT(func(v *ManagedDatabasesChangeDatabaseParameter) ManagedDatabasesChangeDatabaseParameterDatabaseCredentialOutput {
		return v.DatabaseCredential
	}).(ManagedDatabasesChangeDatabaseParameterDatabaseCredentialOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
func (o ManagedDatabasesChangeDatabaseParameterOutput) ManagedDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v *ManagedDatabasesChangeDatabaseParameter) pulumi.StringOutput { return v.ManagedDatabaseId }).(pulumi.StringOutput)
}

// A list of database parameters and their values.
func (o ManagedDatabasesChangeDatabaseParameterOutput) Parameters() ManagedDatabasesChangeDatabaseParameterParameterArrayOutput {
	return o.ApplyT(func(v *ManagedDatabasesChangeDatabaseParameter) ManagedDatabasesChangeDatabaseParameterParameterArrayOutput {
		return v.Parameters
	}).(ManagedDatabasesChangeDatabaseParameterParameterArrayOutput)
}

// The clause used to specify when the parameter change takes effect.
//
// Use `MEMORY` to make the change in memory and affect it immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ManagedDatabasesChangeDatabaseParameterOutput) Scope() pulumi.StringOutput {
	return o.ApplyT(func(v *ManagedDatabasesChangeDatabaseParameter) pulumi.StringOutput { return v.Scope }).(pulumi.StringOutput)
}

type ManagedDatabasesChangeDatabaseParameterArrayOutput struct{ *pulumi.OutputState }

func (ManagedDatabasesChangeDatabaseParameterArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ManagedDatabasesChangeDatabaseParameter)(nil)).Elem()
}

func (o ManagedDatabasesChangeDatabaseParameterArrayOutput) ToManagedDatabasesChangeDatabaseParameterArrayOutput() ManagedDatabasesChangeDatabaseParameterArrayOutput {
	return o
}

func (o ManagedDatabasesChangeDatabaseParameterArrayOutput) ToManagedDatabasesChangeDatabaseParameterArrayOutputWithContext(ctx context.Context) ManagedDatabasesChangeDatabaseParameterArrayOutput {
	return o
}

func (o ManagedDatabasesChangeDatabaseParameterArrayOutput) Index(i pulumi.IntInput) ManagedDatabasesChangeDatabaseParameterOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ManagedDatabasesChangeDatabaseParameter {
		return vs[0].([]*ManagedDatabasesChangeDatabaseParameter)[vs[1].(int)]
	}).(ManagedDatabasesChangeDatabaseParameterOutput)
}

type ManagedDatabasesChangeDatabaseParameterMapOutput struct{ *pulumi.OutputState }

func (ManagedDatabasesChangeDatabaseParameterMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ManagedDatabasesChangeDatabaseParameter)(nil)).Elem()
}

func (o ManagedDatabasesChangeDatabaseParameterMapOutput) ToManagedDatabasesChangeDatabaseParameterMapOutput() ManagedDatabasesChangeDatabaseParameterMapOutput {
	return o
}

func (o ManagedDatabasesChangeDatabaseParameterMapOutput) ToManagedDatabasesChangeDatabaseParameterMapOutputWithContext(ctx context.Context) ManagedDatabasesChangeDatabaseParameterMapOutput {
	return o
}

func (o ManagedDatabasesChangeDatabaseParameterMapOutput) MapIndex(k pulumi.StringInput) ManagedDatabasesChangeDatabaseParameterOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ManagedDatabasesChangeDatabaseParameter {
		return vs[0].(map[string]*ManagedDatabasesChangeDatabaseParameter)[vs[1].(string)]
	}).(ManagedDatabasesChangeDatabaseParameterOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedDatabasesChangeDatabaseParameterInput)(nil)).Elem(), &ManagedDatabasesChangeDatabaseParameter{})
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedDatabasesChangeDatabaseParameterArrayInput)(nil)).Elem(), ManagedDatabasesChangeDatabaseParameterArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedDatabasesChangeDatabaseParameterMapInput)(nil)).Elem(), ManagedDatabasesChangeDatabaseParameterMap{})
	pulumi.RegisterOutputType(ManagedDatabasesChangeDatabaseParameterOutput{})
	pulumi.RegisterOutputType(ManagedDatabasesChangeDatabaseParameterArrayOutput{})
	pulumi.RegisterOutputType(ManagedDatabasesChangeDatabaseParameterMapOutput{})
}
