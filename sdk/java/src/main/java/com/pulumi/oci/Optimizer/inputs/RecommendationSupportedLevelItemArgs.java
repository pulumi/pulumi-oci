// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RecommendationSupportedLevelItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final RecommendationSupportedLevelItemArgs Empty = new RecommendationSupportedLevelItemArgs();

    /**
     * The name of the profile level.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name of the profile level.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private RecommendationSupportedLevelItemArgs() {}

    private RecommendationSupportedLevelItemArgs(RecommendationSupportedLevelItemArgs $) {
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RecommendationSupportedLevelItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RecommendationSupportedLevelItemArgs $;

        public Builder() {
            $ = new RecommendationSupportedLevelItemArgs();
        }

        public Builder(RecommendationSupportedLevelItemArgs defaults) {
            $ = new RecommendationSupportedLevelItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name The name of the profile level.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name of the profile level.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public RecommendationSupportedLevelItemArgs build() {
            return $;
        }
    }

}