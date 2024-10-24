// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ObjectStorage.inputs.GetPrivateEndpointSummariesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPrivateEndpointSummariesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPrivateEndpointSummariesArgs Empty = new GetPrivateEndpointSummariesArgs();

    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetPrivateEndpointSummariesFilterArgs>> filters;

    public Optional<Output<List<GetPrivateEndpointSummariesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    @Import(name="namespace", required=true)
    private Output<String> namespace;

    public Output<String> namespace() {
        return this.namespace;
    }

    private GetPrivateEndpointSummariesArgs() {}

    private GetPrivateEndpointSummariesArgs(GetPrivateEndpointSummariesArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPrivateEndpointSummariesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPrivateEndpointSummariesArgs $;

        public Builder() {
            $ = new GetPrivateEndpointSummariesArgs();
        }

        public Builder(GetPrivateEndpointSummariesArgs defaults) {
            $ = new GetPrivateEndpointSummariesArgs(Objects.requireNonNull(defaults));
        }

        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetPrivateEndpointSummariesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetPrivateEndpointSummariesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetPrivateEndpointSummariesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        public GetPrivateEndpointSummariesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetPrivateEndpointSummariesArgs", "compartmentId");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("GetPrivateEndpointSummariesArgs", "namespace");
            }
            return $;
        }
    }

}
