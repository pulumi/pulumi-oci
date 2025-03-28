// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Analytics;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Analytics.AnalyticsInstanceVanityUrlArgs;
import com.pulumi.oci.Analytics.inputs.AnalyticsInstanceVanityUrlState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Analytics Instance Vanity Url resource in Oracle Cloud Infrastructure Analytics service.
 * 
 * Allows specifying a custom host name to be used to access the analytics instance.  This requires prior setup of DNS entry and certificate
 * for this host.
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
 * import com.pulumi.oci.Analytics.AnalyticsInstanceVanityUrl;
 * import com.pulumi.oci.Analytics.AnalyticsInstanceVanityUrlArgs;
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
 *         var testAnalyticsInstanceVanityUrl = new AnalyticsInstanceVanityUrl("testAnalyticsInstanceVanityUrl", AnalyticsInstanceVanityUrlArgs.builder()
 *             .analyticsInstanceId(testAnalyticsInstance.id())
 *             .caCertificate(analyticsInstanceVanityUrlCaCertificate)
 *             .hosts(analyticsInstanceVanityUrlHosts)
 *             .privateKey(analyticsInstanceVanityUrlPrivateKey)
 *             .publicCertificate(analyticsInstanceVanityUrlPublicCertificate)
 *             .description(analyticsInstanceVanityUrlDescription)
 *             .passphrase(analyticsInstanceVanityUrlPassphrase)
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
 * AnalyticsInstanceVanityUrls can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Analytics/analyticsInstanceVanityUrl:AnalyticsInstanceVanityUrl test_analytics_instance_vanity_url &#34;analyticsInstances/{analyticsInstanceId}/vanityUrls/{vanityUrlKey}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Analytics/analyticsInstanceVanityUrl:AnalyticsInstanceVanityUrl")
public class AnalyticsInstanceVanityUrl extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the AnalyticsInstance.
     * 
     */
    @Export(name="analyticsInstanceId", refs={String.class}, tree="[0]")
    private Output<String> analyticsInstanceId;

    /**
     * @return The OCID of the AnalyticsInstance.
     * 
     */
    public Output<String> analyticsInstanceId() {
        return this.analyticsInstanceId;
    }
    /**
     * (Updatable) PEM CA certificate(s) for HTTPS connections. This may include multiple PEM certificates.
     * 
     */
    @Export(name="caCertificate", refs={String.class}, tree="[0]")
    private Output<String> caCertificate;

    /**
     * @return (Updatable) PEM CA certificate(s) for HTTPS connections. This may include multiple PEM certificates.
     * 
     */
    public Output<String> caCertificate() {
        return this.caCertificate;
    }
    /**
     * Optional description.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> description;

    /**
     * @return Optional description.
     * 
     */
    public Output<Optional<String>> description() {
        return Codegen.optional(this.description);
    }
    /**
     * List of fully qualified hostnames supported by this vanity URL definition (max of 3).
     * 
     */
    @Export(name="hosts", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> hosts;

    /**
     * @return List of fully qualified hostnames supported by this vanity URL definition (max of 3).
     * 
     */
    public Output<List<String>> hosts() {
        return this.hosts;
    }
    /**
     * (Updatable) Passphrase for the PEM Private key (if any).
     * 
     */
    @Export(name="passphrase", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> passphrase;

    /**
     * @return (Updatable) Passphrase for the PEM Private key (if any).
     * 
     */
    public Output<Optional<String>> passphrase() {
        return Codegen.optional(this.passphrase);
    }
    /**
     * (Updatable) PEM Private key for HTTPS connections.
     * 
     */
    @Export(name="privateKey", refs={String.class}, tree="[0]")
    private Output<String> privateKey;

    /**
     * @return (Updatable) PEM Private key for HTTPS connections.
     * 
     */
    public Output<String> privateKey() {
        return this.privateKey;
    }
    /**
     * (Updatable) PEM certificate for HTTPS connections.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="publicCertificate", refs={String.class}, tree="[0]")
    private Output<String> publicCertificate;

    /**
     * @return (Updatable) PEM certificate for HTTPS connections.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> publicCertificate() {
        return this.publicCertificate;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public AnalyticsInstanceVanityUrl(java.lang.String name) {
        this(name, AnalyticsInstanceVanityUrlArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public AnalyticsInstanceVanityUrl(java.lang.String name, AnalyticsInstanceVanityUrlArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public AnalyticsInstanceVanityUrl(java.lang.String name, AnalyticsInstanceVanityUrlArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Analytics/analyticsInstanceVanityUrl:AnalyticsInstanceVanityUrl", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private AnalyticsInstanceVanityUrl(java.lang.String name, Output<java.lang.String> id, @Nullable AnalyticsInstanceVanityUrlState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Analytics/analyticsInstanceVanityUrl:AnalyticsInstanceVanityUrl", name, state, makeResourceOptions(options, id), false);
    }

    private static AnalyticsInstanceVanityUrlArgs makeArgs(AnalyticsInstanceVanityUrlArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? AnalyticsInstanceVanityUrlArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .additionalSecretOutputs(List.of(
                "passphrase",
                "privateKey"
            ))
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
    public static AnalyticsInstanceVanityUrl get(java.lang.String name, Output<java.lang.String> id, @Nullable AnalyticsInstanceVanityUrlState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new AnalyticsInstanceVanityUrl(name, id, state, options);
    }
}
