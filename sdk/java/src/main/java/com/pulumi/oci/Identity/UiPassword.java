// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Identity.UiPasswordArgs;
import com.pulumi.oci.Identity.inputs.UiPasswordState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Ui Password resource in Oracle Cloud Infrastructure Identity service.
 * 
 * Creates a new Console one-time password for the specified user. For more information about user
 * credentials, see [User Credentials](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/usercredentials.htm).
 * 
 * Use this operation after creating a new user, or if a user forgets their password. The new one-time
 * password is returned to you in the response, and you must securely deliver it to the user. They&#39;ll
 * be prompted to change this password the next time they sign in to the Console. If they don&#39;t change
 * it within 7 days, the password will expire and you&#39;ll need to create a new one-time password for the
 * user.
 * 
 * **Note:** The user&#39;s Console login is the unique name you specified when you created the user
 * (see [CreateUser](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/User/CreateUser)).
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Identity.UiPassword;
 * import com.pulumi.oci.Identity.UiPasswordArgs;
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
 *         var testUiPassword = new UiPassword(&#34;testUiPassword&#34;, UiPasswordArgs.builder()        
 *             .userId(oci_identity_user.test_user().id())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Import is not supported for this resource.
 * 
 */
@ResourceType(type="oci:Identity/uiPassword:UiPassword")
public class UiPassword extends com.pulumi.resources.CustomResource {
    /**
     * The detailed status of INACTIVE lifecycleState.
     * 
     */
    @Export(name="inactiveStatus", type=String.class, parameters={})
    private Output<String> inactiveStatus;

    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public Output<String> inactiveStatus() {
        return this.inactiveStatus;
    }
    /**
     * The user&#39;s password for the Console.
     * 
     */
    @Export(name="password", type=String.class, parameters={})
    private Output<String> password;

    /**
     * @return The user&#39;s password for the Console.
     * 
     */
    public Output<String> password() {
        return this.password;
    }
    /**
     * The password&#39;s current state.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The password&#39;s current state.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Date and time the password was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return Date and time the password was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The OCID of the user.
     * 
     */
    @Export(name="userId", type=String.class, parameters={})
    private Output<String> userId;

    /**
     * @return The OCID of the user.
     * 
     */
    public Output<String> userId() {
        return this.userId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public UiPassword(String name) {
        this(name, UiPasswordArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public UiPassword(String name, UiPasswordArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public UiPassword(String name, UiPasswordArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/uiPassword:UiPassword", name, args == null ? UiPasswordArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private UiPassword(String name, Output<String> id, @Nullable UiPasswordState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/uiPassword:UiPassword", name, state, makeResourceOptions(options, id));
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
    public static UiPassword get(String name, Output<String> id, @Nullable UiPasswordState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new UiPassword(name, id, state, options);
    }
}