// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceCatalog.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ServiceCatalog.inputs.PrivateApplicationLogoArgs;
import com.pulumi.oci.ServiceCatalog.inputs.PrivateApplicationPackageDetailsArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PrivateApplicationState extends com.pulumi.resources.ResourceArgs {

    public static final PrivateApplicationState Empty = new PrivateApplicationState();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The name of the private application.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The name of the private application.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
     * 
     */
    @Import(name="logoFileBase64encoded")
    private @Nullable Output<String> logoFileBase64encoded;

    /**
     * @return (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
     * 
     */
    public Optional<Output<String>> logoFileBase64encoded() {
        return Optional.ofNullable(this.logoFileBase64encoded);
    }

    /**
     * The model for uploaded binary data, like logos and images.
     * 
     */
    @Import(name="logos")
    private @Nullable Output<List<PrivateApplicationLogoArgs>> logos;

    /**
     * @return The model for uploaded binary data, like logos and images.
     * 
     */
    public Optional<Output<List<PrivateApplicationLogoArgs>>> logos() {
        return Optional.ofNullable(this.logos);
    }

    /**
     * (Updatable) A long description of the private application.
     * 
     */
    @Import(name="longDescription")
    private @Nullable Output<String> longDescription;

    /**
     * @return (Updatable) A long description of the private application.
     * 
     */
    public Optional<Output<String>> longDescription() {
        return Optional.ofNullable(this.longDescription);
    }

    /**
     * A base object for creating a private application package.
     * 
     */
    @Import(name="packageDetails")
    private @Nullable Output<PrivateApplicationPackageDetailsArgs> packageDetails;

    /**
     * @return A base object for creating a private application package.
     * 
     */
    public Optional<Output<PrivateApplicationPackageDetailsArgs>> packageDetails() {
        return Optional.ofNullable(this.packageDetails);
    }

    /**
     * Type of packages within this private application.
     * 
     */
    @Import(name="packageType")
    private @Nullable Output<String> packageType;

    /**
     * @return Type of packages within this private application.
     * 
     */
    public Optional<Output<String>> packageType() {
        return Optional.ofNullable(this.packageType);
    }

    /**
     * (Updatable) A short description of the private application.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="shortDescription")
    private @Nullable Output<String> shortDescription;

    /**
     * @return (Updatable) A short description of the private application.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> shortDescription() {
        return Optional.ofNullable(this.shortDescription);
    }

    /**
     * The lifecycle state of the private application.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The lifecycle state of the private application.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private PrivateApplicationState() {}

    private PrivateApplicationState(PrivateApplicationState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.logoFileBase64encoded = $.logoFileBase64encoded;
        this.logos = $.logos;
        this.longDescription = $.longDescription;
        this.packageDetails = $.packageDetails;
        this.packageType = $.packageType;
        this.shortDescription = $.shortDescription;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PrivateApplicationState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PrivateApplicationState $;

        public Builder() {
            $ = new PrivateApplicationState();
        }

        public Builder(PrivateApplicationState defaults) {
            $ = new PrivateApplicationState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the private application.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) The name of the private application.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The name of the private application.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param logoFileBase64encoded (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
         * 
         * @return builder
         * 
         */
        public Builder logoFileBase64encoded(@Nullable Output<String> logoFileBase64encoded) {
            $.logoFileBase64encoded = logoFileBase64encoded;
            return this;
        }

        /**
         * @param logoFileBase64encoded (Updatable) Base64-encoded logo to use as the private application icon. Template icon file requirements: PNG format, 50 KB maximum, 130 x 130 pixels.
         * 
         * @return builder
         * 
         */
        public Builder logoFileBase64encoded(String logoFileBase64encoded) {
            return logoFileBase64encoded(Output.of(logoFileBase64encoded));
        }

        /**
         * @param logos The model for uploaded binary data, like logos and images.
         * 
         * @return builder
         * 
         */
        public Builder logos(@Nullable Output<List<PrivateApplicationLogoArgs>> logos) {
            $.logos = logos;
            return this;
        }

        /**
         * @param logos The model for uploaded binary data, like logos and images.
         * 
         * @return builder
         * 
         */
        public Builder logos(List<PrivateApplicationLogoArgs> logos) {
            return logos(Output.of(logos));
        }

        /**
         * @param logos The model for uploaded binary data, like logos and images.
         * 
         * @return builder
         * 
         */
        public Builder logos(PrivateApplicationLogoArgs... logos) {
            return logos(List.of(logos));
        }

        /**
         * @param longDescription (Updatable) A long description of the private application.
         * 
         * @return builder
         * 
         */
        public Builder longDescription(@Nullable Output<String> longDescription) {
            $.longDescription = longDescription;
            return this;
        }

        /**
         * @param longDescription (Updatable) A long description of the private application.
         * 
         * @return builder
         * 
         */
        public Builder longDescription(String longDescription) {
            return longDescription(Output.of(longDescription));
        }

        /**
         * @param packageDetails A base object for creating a private application package.
         * 
         * @return builder
         * 
         */
        public Builder packageDetails(@Nullable Output<PrivateApplicationPackageDetailsArgs> packageDetails) {
            $.packageDetails = packageDetails;
            return this;
        }

        /**
         * @param packageDetails A base object for creating a private application package.
         * 
         * @return builder
         * 
         */
        public Builder packageDetails(PrivateApplicationPackageDetailsArgs packageDetails) {
            return packageDetails(Output.of(packageDetails));
        }

        /**
         * @param packageType Type of packages within this private application.
         * 
         * @return builder
         * 
         */
        public Builder packageType(@Nullable Output<String> packageType) {
            $.packageType = packageType;
            return this;
        }

        /**
         * @param packageType Type of packages within this private application.
         * 
         * @return builder
         * 
         */
        public Builder packageType(String packageType) {
            return packageType(Output.of(packageType));
        }

        /**
         * @param shortDescription (Updatable) A short description of the private application.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder shortDescription(@Nullable Output<String> shortDescription) {
            $.shortDescription = shortDescription;
            return this;
        }

        /**
         * @param shortDescription (Updatable) A short description of the private application.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder shortDescription(String shortDescription) {
            return shortDescription(Output.of(shortDescription));
        }

        /**
         * @param state The lifecycle state of the private application.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The lifecycle state of the private application.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public PrivateApplicationState build() {
            return $;
        }
    }

}
