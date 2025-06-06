// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.inputs.GetRepositoryAuthorsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRepositoryAuthorsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRepositoryAuthorsArgs Empty = new GetRepositoryAuthorsArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetRepositoryAuthorsFilterArgs>> filters;

    public Optional<Output<List<GetRepositoryAuthorsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given reference name.
     * 
     */
    @Import(name="refName")
    private @Nullable Output<String> refName;

    /**
     * @return A filter to return only resources that match the given reference name.
     * 
     */
    public Optional<Output<String>> refName() {
        return Optional.ofNullable(this.refName);
    }

    /**
     * Unique repository identifier.
     * 
     */
    @Import(name="repositoryId", required=true)
    private Output<String> repositoryId;

    /**
     * @return Unique repository identifier.
     * 
     */
    public Output<String> repositoryId() {
        return this.repositoryId;
    }

    private GetRepositoryAuthorsArgs() {}

    private GetRepositoryAuthorsArgs(GetRepositoryAuthorsArgs $) {
        this.filters = $.filters;
        this.refName = $.refName;
        this.repositoryId = $.repositoryId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRepositoryAuthorsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRepositoryAuthorsArgs $;

        public Builder() {
            $ = new GetRepositoryAuthorsArgs();
        }

        public Builder(GetRepositoryAuthorsArgs defaults) {
            $ = new GetRepositoryAuthorsArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetRepositoryAuthorsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetRepositoryAuthorsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetRepositoryAuthorsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param refName A filter to return only resources that match the given reference name.
         * 
         * @return builder
         * 
         */
        public Builder refName(@Nullable Output<String> refName) {
            $.refName = refName;
            return this;
        }

        /**
         * @param refName A filter to return only resources that match the given reference name.
         * 
         * @return builder
         * 
         */
        public Builder refName(String refName) {
            return refName(Output.of(refName));
        }

        /**
         * @param repositoryId Unique repository identifier.
         * 
         * @return builder
         * 
         */
        public Builder repositoryId(Output<String> repositoryId) {
            $.repositoryId = repositoryId;
            return this;
        }

        /**
         * @param repositoryId Unique repository identifier.
         * 
         * @return builder
         * 
         */
        public Builder repositoryId(String repositoryId) {
            return repositoryId(Output.of(repositoryId));
        }

        public GetRepositoryAuthorsArgs build() {
            if ($.repositoryId == null) {
                throw new MissingRequiredPropertyException("GetRepositoryAuthorsArgs", "repositoryId");
            }
            return $;
        }
    }

}
