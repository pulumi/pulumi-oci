// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.inputs.GetPrivateEndpointsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPrivateEndpointsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPrivateEndpointsArgs Empty = new GetPrivateEndpointsArgs();

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     * 
     */
    @Import(name="createdBy")
    private @Nullable Output<String> createdBy;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     * 
     */
    public Optional<Output<String>> createdBy() {
        return Optional.ofNullable(this.createdBy);
    }

    /**
     * Resource types in the Data Science service such as notebooks.
     * 
     */
    @Import(name="dataScienceResourceType")
    private @Nullable Output<String> dataScienceResourceType;

    /**
     * @return Resource types in the Data Science service such as notebooks.
     * 
     */
    public Optional<Output<String>> dataScienceResourceType() {
        return Optional.ofNullable(this.dataScienceResourceType);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetPrivateEndpointsFilterArgs>> filters;

    public Optional<Output<List<GetPrivateEndpointsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The lifecycle state of the private endpoint.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The lifecycle state of the private endpoint.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetPrivateEndpointsArgs() {}

    private GetPrivateEndpointsArgs(GetPrivateEndpointsArgs $) {
        this.compartmentId = $.compartmentId;
        this.createdBy = $.createdBy;
        this.dataScienceResourceType = $.dataScienceResourceType;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPrivateEndpointsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPrivateEndpointsArgs $;

        public Builder() {
            $ = new GetPrivateEndpointsArgs();
        }

        public Builder(GetPrivateEndpointsArgs defaults) {
            $ = new GetPrivateEndpointsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param createdBy &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(@Nullable Output<String> createdBy) {
            $.createdBy = createdBy;
            return this;
        }

        /**
         * @param createdBy &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(String createdBy) {
            return createdBy(Output.of(createdBy));
        }

        /**
         * @param dataScienceResourceType Resource types in the Data Science service such as notebooks.
         * 
         * @return builder
         * 
         */
        public Builder dataScienceResourceType(@Nullable Output<String> dataScienceResourceType) {
            $.dataScienceResourceType = dataScienceResourceType;
            return this;
        }

        /**
         * @param dataScienceResourceType Resource types in the Data Science service such as notebooks.
         * 
         * @return builder
         * 
         */
        public Builder dataScienceResourceType(String dataScienceResourceType) {
            return dataScienceResourceType(Output.of(dataScienceResourceType));
        }

        /**
         * @param displayName &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetPrivateEndpointsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetPrivateEndpointsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetPrivateEndpointsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state The lifecycle state of the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The lifecycle state of the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetPrivateEndpointsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetPrivateEndpointsArgs", "compartmentId");
            }
            return $;
        }
    }

}
