// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.inputs.GetNamespaceEffectivePropertiesFilterArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetNamespaceEffectivePropertiesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNamespaceEffectivePropertiesArgs Empty = new GetNamespaceEffectivePropertiesArgs();

    /**
     * The agent ocid.
     * 
     */
    @Import(name="agentId")
    private @Nullable Output<String> agentId;

    /**
     * @return The agent ocid.
     * 
     */
    public Optional<Output<String>> agentId() {
        return Optional.ofNullable(this.agentId);
    }

    /**
     * The entity ocid.
     * 
     */
    @Import(name="entityId")
    private @Nullable Output<String> entityId;

    /**
     * @return The entity ocid.
     * 
     */
    public Optional<Output<String>> entityId() {
        return Optional.ofNullable(this.entityId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetNamespaceEffectivePropertiesFilterArgs>> filters;

    public Optional<Output<List<GetNamespaceEffectivePropertiesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The include pattern flag.
     * 
     */
    @Import(name="isIncludePatterns")
    private @Nullable Output<Boolean> isIncludePatterns;

    /**
     * @return The include pattern flag.
     * 
     */
    public Optional<Output<Boolean>> isIncludePatterns() {
        return Optional.ofNullable(this.isIncludePatterns);
    }

    /**
     * The property name used for filtering.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The property name used for filtering.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * The pattern id.
     * 
     */
    @Import(name="patternId")
    private @Nullable Output<Integer> patternId;

    /**
     * @return The pattern id.
     * 
     */
    public Optional<Output<Integer>> patternId() {
        return Optional.ofNullable(this.patternId);
    }

    /**
     * The pattern id (long).
     * 
     */
    @Import(name="patternIdLong")
    private @Nullable Output<String> patternIdLong;

    /**
     * @return The pattern id (long).
     * 
     */
    public Optional<Output<String>> patternIdLong() {
        return Optional.ofNullable(this.patternIdLong);
    }

    /**
     * The source name.
     * 
     */
    @Import(name="sourceName")
    private @Nullable Output<String> sourceName;

    /**
     * @return The source name.
     * 
     */
    public Optional<Output<String>> sourceName() {
        return Optional.ofNullable(this.sourceName);
    }

    private GetNamespaceEffectivePropertiesArgs() {}

    private GetNamespaceEffectivePropertiesArgs(GetNamespaceEffectivePropertiesArgs $) {
        this.agentId = $.agentId;
        this.entityId = $.entityId;
        this.filters = $.filters;
        this.isIncludePatterns = $.isIncludePatterns;
        this.name = $.name;
        this.namespace = $.namespace;
        this.patternId = $.patternId;
        this.patternIdLong = $.patternIdLong;
        this.sourceName = $.sourceName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNamespaceEffectivePropertiesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNamespaceEffectivePropertiesArgs $;

        public Builder() {
            $ = new GetNamespaceEffectivePropertiesArgs();
        }

        public Builder(GetNamespaceEffectivePropertiesArgs defaults) {
            $ = new GetNamespaceEffectivePropertiesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param agentId The agent ocid.
         * 
         * @return builder
         * 
         */
        public Builder agentId(@Nullable Output<String> agentId) {
            $.agentId = agentId;
            return this;
        }

        /**
         * @param agentId The agent ocid.
         * 
         * @return builder
         * 
         */
        public Builder agentId(String agentId) {
            return agentId(Output.of(agentId));
        }

        /**
         * @param entityId The entity ocid.
         * 
         * @return builder
         * 
         */
        public Builder entityId(@Nullable Output<String> entityId) {
            $.entityId = entityId;
            return this;
        }

        /**
         * @param entityId The entity ocid.
         * 
         * @return builder
         * 
         */
        public Builder entityId(String entityId) {
            return entityId(Output.of(entityId));
        }

        public Builder filters(@Nullable Output<List<GetNamespaceEffectivePropertiesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetNamespaceEffectivePropertiesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetNamespaceEffectivePropertiesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isIncludePatterns The include pattern flag.
         * 
         * @return builder
         * 
         */
        public Builder isIncludePatterns(@Nullable Output<Boolean> isIncludePatterns) {
            $.isIncludePatterns = isIncludePatterns;
            return this;
        }

        /**
         * @param isIncludePatterns The include pattern flag.
         * 
         * @return builder
         * 
         */
        public Builder isIncludePatterns(Boolean isIncludePatterns) {
            return isIncludePatterns(Output.of(isIncludePatterns));
        }

        /**
         * @param name The property name used for filtering.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The property name used for filtering.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param patternId The pattern id.
         * 
         * @return builder
         * 
         */
        public Builder patternId(@Nullable Output<Integer> patternId) {
            $.patternId = patternId;
            return this;
        }

        /**
         * @param patternId The pattern id.
         * 
         * @return builder
         * 
         */
        public Builder patternId(Integer patternId) {
            return patternId(Output.of(patternId));
        }

        /**
         * @param patternIdLong The pattern id (long).
         * 
         * @return builder
         * 
         */
        public Builder patternIdLong(@Nullable Output<String> patternIdLong) {
            $.patternIdLong = patternIdLong;
            return this;
        }

        /**
         * @param patternIdLong The pattern id (long).
         * 
         * @return builder
         * 
         */
        public Builder patternIdLong(String patternIdLong) {
            return patternIdLong(Output.of(patternIdLong));
        }

        /**
         * @param sourceName The source name.
         * 
         * @return builder
         * 
         */
        public Builder sourceName(@Nullable Output<String> sourceName) {
            $.sourceName = sourceName;
            return this;
        }

        /**
         * @param sourceName The source name.
         * 
         * @return builder
         * 
         */
        public Builder sourceName(String sourceName) {
            return sourceName(Output.of(sourceName));
        }

        public GetNamespaceEffectivePropertiesArgs build() {
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("GetNamespaceEffectivePropertiesArgs", "namespace");
            }
            return $;
        }
    }

}
