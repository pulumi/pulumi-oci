// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TriggerActionFilterExcludeFileFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final TriggerActionFilterExcludeFileFilterArgs Empty = new TriggerActionFilterExcludeFileFilterArgs();

    /**
     * The file paths/glob pattern for files.
     * 
     */
    @Import(name="filePaths")
    private @Nullable Output<List<String>> filePaths;

    /**
     * @return The file paths/glob pattern for files.
     * 
     */
    public Optional<Output<List<String>>> filePaths() {
        return Optional.ofNullable(this.filePaths);
    }

    private TriggerActionFilterExcludeFileFilterArgs() {}

    private TriggerActionFilterExcludeFileFilterArgs(TriggerActionFilterExcludeFileFilterArgs $) {
        this.filePaths = $.filePaths;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TriggerActionFilterExcludeFileFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TriggerActionFilterExcludeFileFilterArgs $;

        public Builder() {
            $ = new TriggerActionFilterExcludeFileFilterArgs();
        }

        public Builder(TriggerActionFilterExcludeFileFilterArgs defaults) {
            $ = new TriggerActionFilterExcludeFileFilterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param filePaths The file paths/glob pattern for files.
         * 
         * @return builder
         * 
         */
        public Builder filePaths(@Nullable Output<List<String>> filePaths) {
            $.filePaths = filePaths;
            return this;
        }

        /**
         * @param filePaths The file paths/glob pattern for files.
         * 
         * @return builder
         * 
         */
        public Builder filePaths(List<String> filePaths) {
            return filePaths(Output.of(filePaths));
        }

        /**
         * @param filePaths The file paths/glob pattern for files.
         * 
         * @return builder
         * 
         */
        public Builder filePaths(String... filePaths) {
            return filePaths(List.of(filePaths));
        }

        public TriggerActionFilterExcludeFileFilterArgs build() {
            return $;
        }
    }

}
