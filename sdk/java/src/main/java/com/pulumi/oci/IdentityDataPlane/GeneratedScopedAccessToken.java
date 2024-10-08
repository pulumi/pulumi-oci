// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.IdentityDataPlane;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.IdentityDataPlane.GeneratedScopedAccessTokenArgs;
import com.pulumi.oci.IdentityDataPlane.inputs.GeneratedScopedAccessTokenState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Generate Scoped Access Token resource in Oracle Cloud Infrastructure Identity Data Plane service.
 * 
 * Based on the calling principal and the input payload, derive the claims and create a security token.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.IdentityDataPlane.GeneratedScopedAccessToken;
 * import com.pulumi.oci.IdentityDataPlane.GeneratedScopedAccessTokenArgs;
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
 *         var testGenerateScopedAccessToken = new GeneratedScopedAccessToken("testGenerateScopedAccessToken", GeneratedScopedAccessTokenArgs.builder()
 *             .publicKey(generateScopedAccessTokenPublicKey)
 *             .scope(generateScopedAccessTokenScope)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * GenerateScopedAccessToken can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:IdentityDataPlane/generatedScopedAccessToken:GeneratedScopedAccessToken test_generate_scoped_access_token &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:IdentityDataPlane/generatedScopedAccessToken:GeneratedScopedAccessToken")
public class GeneratedScopedAccessToken extends com.pulumi.resources.CustomResource {
    /**
     * A temporary public key, owned by the service. The service also owns the corresponding private key. This public key will by put inside the security token by the auth service after successful validation of the certificate.
     * 
     */
    @Export(name="publicKey", refs={String.class}, tree="[0]")
    private Output<String> publicKey;

    /**
     * @return A temporary public key, owned by the service. The service also owns the corresponding private key. This public key will by put inside the security token by the auth service after successful validation of the certificate.
     * 
     */
    public Output<String> publicKey() {
        return this.publicKey;
    }
    /**
     * Scope definition for the scoped access token
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="scope", refs={String.class}, tree="[0]")
    private Output<String> scope;

    /**
     * @return Scope definition for the scoped access token
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> scope() {
        return this.scope;
    }
    /**
     * The security token, signed by auth service
     * 
     */
    @Export(name="token", refs={String.class}, tree="[0]")
    private Output<String> token;

    /**
     * @return The security token, signed by auth service
     * 
     */
    public Output<String> token() {
        return this.token;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public GeneratedScopedAccessToken(java.lang.String name) {
        this(name, GeneratedScopedAccessTokenArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public GeneratedScopedAccessToken(java.lang.String name, GeneratedScopedAccessTokenArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public GeneratedScopedAccessToken(java.lang.String name, GeneratedScopedAccessTokenArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:IdentityDataPlane/generatedScopedAccessToken:GeneratedScopedAccessToken", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private GeneratedScopedAccessToken(java.lang.String name, Output<java.lang.String> id, @Nullable GeneratedScopedAccessTokenState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:IdentityDataPlane/generatedScopedAccessToken:GeneratedScopedAccessToken", name, state, makeResourceOptions(options, id), false);
    }

    private static GeneratedScopedAccessTokenArgs makeArgs(GeneratedScopedAccessTokenArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? GeneratedScopedAccessTokenArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
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
    public static GeneratedScopedAccessToken get(java.lang.String name, Output<java.lang.String> id, @Nullable GeneratedScopedAccessTokenState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new GeneratedScopedAccessToken(name, id, state, options);
    }
}
