// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.TriggerActionFilterExcludeArgs;
import com.pulumi.oci.DevOps.inputs.TriggerActionFilterIncludeArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TriggerActionFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final TriggerActionFilterArgs Empty = new TriggerActionFilterArgs();

    /**
     * (Updatable) The events, for example, PUSH, PULL_REQUEST_MERGE.
     * 
     */
    @Import(name="events")
    private @Nullable Output<List<String>> events;

    /**
     * @return (Updatable) The events, for example, PUSH, PULL_REQUEST_MERGE.
     * 
     */
    public Optional<Output<List<String>>> events() {
        return Optional.ofNullable(this.events);
    }

    @Import(name="exclude")
    private @Nullable Output<TriggerActionFilterExcludeArgs> exclude;

    public Optional<Output<TriggerActionFilterExcludeArgs>> exclude() {
        return Optional.ofNullable(this.exclude);
    }

    /**
     * (Updatable) Attributes to filter GitLab self-hosted server events.
     * 
     */
    @Import(name="include")
    private @Nullable Output<TriggerActionFilterIncludeArgs> include;

    /**
     * @return (Updatable) Attributes to filter GitLab self-hosted server events.
     * 
     */
    public Optional<Output<TriggerActionFilterIncludeArgs>> include() {
        return Optional.ofNullable(this.include);
    }

    /**
     * (Updatable) Source of the trigger. Allowed values are, GITHUB,GITLAB and BITBUCKET_CLOUD.
     * 
     */
    @Import(name="triggerSource", required=true)
    private Output<String> triggerSource;

    /**
     * @return (Updatable) Source of the trigger. Allowed values are, GITHUB,GITLAB and BITBUCKET_CLOUD.
     * 
     */
    public Output<String> triggerSource() {
        return this.triggerSource;
    }

    private TriggerActionFilterArgs() {}

    private TriggerActionFilterArgs(TriggerActionFilterArgs $) {
        this.events = $.events;
        this.exclude = $.exclude;
        this.include = $.include;
        this.triggerSource = $.triggerSource;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TriggerActionFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TriggerActionFilterArgs $;

        public Builder() {
            $ = new TriggerActionFilterArgs();
        }

        public Builder(TriggerActionFilterArgs defaults) {
            $ = new TriggerActionFilterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param events (Updatable) The events, for example, PUSH, PULL_REQUEST_MERGE.
         * 
         * @return builder
         * 
         */
        public Builder events(@Nullable Output<List<String>> events) {
            $.events = events;
            return this;
        }

        /**
         * @param events (Updatable) The events, for example, PUSH, PULL_REQUEST_MERGE.
         * 
         * @return builder
         * 
         */
        public Builder events(List<String> events) {
            return events(Output.of(events));
        }

        /**
         * @param events (Updatable) The events, for example, PUSH, PULL_REQUEST_MERGE.
         * 
         * @return builder
         * 
         */
        public Builder events(String... events) {
            return events(List.of(events));
        }

        public Builder exclude(@Nullable Output<TriggerActionFilterExcludeArgs> exclude) {
            $.exclude = exclude;
            return this;
        }

        public Builder exclude(TriggerActionFilterExcludeArgs exclude) {
            return exclude(Output.of(exclude));
        }

        /**
         * @param include (Updatable) Attributes to filter GitLab self-hosted server events.
         * 
         * @return builder
         * 
         */
        public Builder include(@Nullable Output<TriggerActionFilterIncludeArgs> include) {
            $.include = include;
            return this;
        }

        /**
         * @param include (Updatable) Attributes to filter GitLab self-hosted server events.
         * 
         * @return builder
         * 
         */
        public Builder include(TriggerActionFilterIncludeArgs include) {
            return include(Output.of(include));
        }

        /**
         * @param triggerSource (Updatable) Source of the trigger. Allowed values are, GITHUB,GITLAB and BITBUCKET_CLOUD.
         * 
         * @return builder
         * 
         */
        public Builder triggerSource(Output<String> triggerSource) {
            $.triggerSource = triggerSource;
            return this;
        }

        /**
         * @param triggerSource (Updatable) Source of the trigger. Allowed values are, GITHUB,GITLAB and BITBUCKET_CLOUD.
         * 
         * @return builder
         * 
         */
        public Builder triggerSource(String triggerSource) {
            return triggerSource(Output.of(triggerSource));
        }

        public TriggerActionFilterArgs build() {
            $.triggerSource = Objects.requireNonNull($.triggerSource, "expected parameter 'triggerSource' to be non-null");
            return $;
        }
    }

}