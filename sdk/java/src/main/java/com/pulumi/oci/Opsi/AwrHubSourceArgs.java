// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AwrHubSourceArgs extends com.pulumi.resources.ResourceArgs {

    public static final AwrHubSourceArgs Empty = new AwrHubSourceArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
     * 
     */
    @Import(name="associatedOpsiId")
    private @Nullable Output<String> associatedOpsiId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
     * 
     */
    public Optional<Output<String>> associatedOpsiId() {
        return Optional.ofNullable(this.associatedOpsiId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
     * 
     */
    @Import(name="associatedResourceId")
    private @Nullable Output<String> associatedResourceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
     * 
     */
    public Optional<Output<String>> associatedResourceId() {
        return Optional.ofNullable(this.associatedResourceId);
    }

    /**
     * AWR Hub OCID
     * 
     */
    @Import(name="awrHubId", required=true)
    private Output<String> awrHubId;

    /**
     * @return AWR Hub OCID
     * 
     */
    public Output<String> awrHubId() {
        return this.awrHubId;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
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
     * The name of the Awr Hub source database.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name of the Awr Hub source database.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) source type of the database
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) source type of the database
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    private AwrHubSourceArgs() {}

    private AwrHubSourceArgs(AwrHubSourceArgs $) {
        this.associatedOpsiId = $.associatedOpsiId;
        this.associatedResourceId = $.associatedResourceId;
        this.awrHubId = $.awrHubId;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.freeformTags = $.freeformTags;
        this.name = $.name;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AwrHubSourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AwrHubSourceArgs $;

        public Builder() {
            $ = new AwrHubSourceArgs();
        }

        public Builder(AwrHubSourceArgs defaults) {
            $ = new AwrHubSourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param associatedOpsiId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
         * 
         * @return builder
         * 
         */
        public Builder associatedOpsiId(@Nullable Output<String> associatedOpsiId) {
            $.associatedOpsiId = associatedOpsiId;
            return this;
        }

        /**
         * @param associatedOpsiId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
         * 
         * @return builder
         * 
         */
        public Builder associatedOpsiId(String associatedOpsiId) {
            return associatedOpsiId(Output.of(associatedOpsiId));
        }

        /**
         * @param associatedResourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
         * 
         * @return builder
         * 
         */
        public Builder associatedResourceId(@Nullable Output<String> associatedResourceId) {
            $.associatedResourceId = associatedResourceId;
            return this;
        }

        /**
         * @param associatedResourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database id.
         * 
         * @return builder
         * 
         */
        public Builder associatedResourceId(String associatedResourceId) {
            return associatedResourceId(Output.of(associatedResourceId));
        }

        /**
         * @param awrHubId AWR Hub OCID
         * 
         * @return builder
         * 
         */
        public Builder awrHubId(Output<String> awrHubId) {
            $.awrHubId = awrHubId;
            return this;
        }

        /**
         * @param awrHubId AWR Hub OCID
         * 
         * @return builder
         * 
         */
        public Builder awrHubId(String awrHubId) {
            return awrHubId(Output.of(awrHubId));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
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
         * @param name The name of the Awr Hub source database.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name of the Awr Hub source database.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param type (Updatable) source type of the database
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) source type of the database
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public AwrHubSourceArgs build() {
            if ($.awrHubId == null) {
                throw new MissingRequiredPropertyException("AwrHubSourceArgs", "awrHubId");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("AwrHubSourceArgs", "compartmentId");
            }
            if ($.type == null) {
                throw new MissingRequiredPropertyException("AwrHubSourceArgs", "type");
            }
            return $;
        }
    }

}
