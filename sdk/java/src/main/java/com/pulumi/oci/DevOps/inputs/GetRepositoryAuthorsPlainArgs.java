// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.GetRepositoryAuthorsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRepositoryAuthorsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRepositoryAuthorsPlainArgs Empty = new GetRepositoryAuthorsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetRepositoryAuthorsFilter> filters;

    public Optional<List<GetRepositoryAuthorsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given reference name.
     * 
     */
    @Import(name="refName")
    private @Nullable String refName;

    /**
     * @return A filter to return only resources that match the given reference name.
     * 
     */
    public Optional<String> refName() {
        return Optional.ofNullable(this.refName);
    }

    /**
     * Unique repository identifier.
     * 
     */
    @Import(name="repositoryId", required=true)
    private String repositoryId;

    /**
     * @return Unique repository identifier.
     * 
     */
    public String repositoryId() {
        return this.repositoryId;
    }

    private GetRepositoryAuthorsPlainArgs() {}

    private GetRepositoryAuthorsPlainArgs(GetRepositoryAuthorsPlainArgs $) {
        this.filters = $.filters;
        this.refName = $.refName;
        this.repositoryId = $.repositoryId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRepositoryAuthorsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRepositoryAuthorsPlainArgs $;

        public Builder() {
            $ = new GetRepositoryAuthorsPlainArgs();
        }

        public Builder(GetRepositoryAuthorsPlainArgs defaults) {
            $ = new GetRepositoryAuthorsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetRepositoryAuthorsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetRepositoryAuthorsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param refName A filter to return only resources that match the given reference name.
         * 
         * @return builder
         * 
         */
        public Builder refName(@Nullable String refName) {
            $.refName = refName;
            return this;
        }

        /**
         * @param repositoryId Unique repository identifier.
         * 
         * @return builder
         * 
         */
        public Builder repositoryId(String repositoryId) {
            $.repositoryId = repositoryId;
            return this;
        }

        public GetRepositoryAuthorsPlainArgs build() {
            $.repositoryId = Objects.requireNonNull($.repositoryId, "expected parameter 'repositoryId' to be non-null");
            return $;
        }
    }

}