// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FusionApps;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.FusionApps.FusionEnvironmentAdminUserArgs;
import com.pulumi.oci.FusionApps.inputs.FusionEnvironmentAdminUserState;
import com.pulumi.oci.FusionApps.outputs.FusionEnvironmentAdminUserItem;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Fusion Environment Admin User resource in Oracle Cloud Infrastructure Fusion Apps service.
 * 
 * Create a FusionEnvironment admin user
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.FusionApps.FusionEnvironmentAdminUser;
 * import com.pulumi.oci.FusionApps.FusionEnvironmentAdminUserArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testFusionEnvironmentAdminUser = new FusionEnvironmentAdminUser(&#34;testFusionEnvironmentAdminUser&#34;, FusionEnvironmentAdminUserArgs.builder()        
 *             .emailAddress(var_.fusion_environment_admin_user_email_address())
 *             .firstName(var_.fusion_environment_admin_user_first_name())
 *             .fusionEnvironmentId(oci_fusion_apps_fusion_environment.test_fusion_environment().id())
 *             .lastName(var_.fusion_environment_admin_user_last_name())
 *             .password(var_.fusion_environment_admin_user_password())
 *             .username(var_.fusion_environment_admin_user_username())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * FusionEnvironmentAdminUsers can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:FusionApps/fusionEnvironmentAdminUser:FusionEnvironmentAdminUser test_fusion_environment_admin_user &#34;fusionEnvironments/{fusionEnvironmentId}/adminUsers/{adminUsername}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:FusionApps/fusionEnvironmentAdminUser:FusionEnvironmentAdminUser")
public class FusionEnvironmentAdminUser extends com.pulumi.resources.CustomResource {
    /**
     * The email address for the administrator.
     * 
     */
    @Export(name="emailAddress", type=String.class, parameters={})
    private Output<String> emailAddress;

    /**
     * @return The email address for the administrator.
     * 
     */
    public Output<String> emailAddress() {
        return this.emailAddress;
    }
    /**
     * The administrator&#39;s first name.
     * 
     */
    @Export(name="firstName", type=String.class, parameters={})
    private Output<String> firstName;

    /**
     * @return The administrator&#39;s first name.
     * 
     */
    public Output<String> firstName() {
        return this.firstName;
    }
    /**
     * unique FusionEnvironment identifier
     * 
     */
    @Export(name="fusionEnvironmentId", type=String.class, parameters={})
    private Output<String> fusionEnvironmentId;

    /**
     * @return unique FusionEnvironment identifier
     * 
     */
    public Output<String> fusionEnvironmentId() {
        return this.fusionEnvironmentId;
    }
    /**
     * A page of AdminUserSummary objects.
     * 
     */
    @Export(name="items", type=List.class, parameters={FusionEnvironmentAdminUserItem.class})
    private Output<List<FusionEnvironmentAdminUserItem>> items;

    /**
     * @return A page of AdminUserSummary objects.
     * 
     */
    public Output<List<FusionEnvironmentAdminUserItem>> items() {
        return this.items;
    }
    /**
     * The administrator&#39;s last name.
     * 
     */
    @Export(name="lastName", type=String.class, parameters={})
    private Output<String> lastName;

    /**
     * @return The administrator&#39;s last name.
     * 
     */
    public Output<String> lastName() {
        return this.lastName;
    }
    /**
     * The password for the administrator.
     * 
     */
    @Export(name="password", type=String.class, parameters={})
    private Output<String> password;

    /**
     * @return The password for the administrator.
     * 
     */
    public Output<String> password() {
        return this.password;
    }
    /**
     * The username for the administrator.
     * 
     */
    @Export(name="username", type=String.class, parameters={})
    private Output<String> username;

    /**
     * @return The username for the administrator.
     * 
     */
    public Output<String> username() {
        return this.username;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public FusionEnvironmentAdminUser(String name) {
        this(name, FusionEnvironmentAdminUserArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public FusionEnvironmentAdminUser(String name, FusionEnvironmentAdminUserArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public FusionEnvironmentAdminUser(String name, FusionEnvironmentAdminUserArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FusionApps/fusionEnvironmentAdminUser:FusionEnvironmentAdminUser", name, args == null ? FusionEnvironmentAdminUserArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private FusionEnvironmentAdminUser(String name, Output<String> id, @Nullable FusionEnvironmentAdminUserState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FusionApps/fusionEnvironmentAdminUser:FusionEnvironmentAdminUser", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static FusionEnvironmentAdminUser get(String name, Output<String> id, @Nullable FusionEnvironmentAdminUserState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new FusionEnvironmentAdminUser(name, id, state, options);
    }
}