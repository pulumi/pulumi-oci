// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MetricExtensionQueryPropertiesSqlDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final MetricExtensionQueryPropertiesSqlDetailsArgs Empty = new MetricExtensionQueryPropertiesSqlDetailsArgs();

    /**
     * (Updatable) Sql statement or script file content as base64 encoded string
     * 
     */
    @Import(name="content", required=true)
    private Output<String> content;

    /**
     * @return (Updatable) Sql statement or script file content as base64 encoded string
     * 
     */
    public Output<String> content() {
        return this.content;
    }

    /**
     * (Updatable) If a script needs to be executed, then provide file name of the script
     * 
     */
    @Import(name="scriptFileName")
    private @Nullable Output<String> scriptFileName;

    /**
     * @return (Updatable) If a script needs to be executed, then provide file name of the script
     * 
     */
    public Optional<Output<String>> scriptFileName() {
        return Optional.ofNullable(this.scriptFileName);
    }

    private MetricExtensionQueryPropertiesSqlDetailsArgs() {}

    private MetricExtensionQueryPropertiesSqlDetailsArgs(MetricExtensionQueryPropertiesSqlDetailsArgs $) {
        this.content = $.content;
        this.scriptFileName = $.scriptFileName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MetricExtensionQueryPropertiesSqlDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MetricExtensionQueryPropertiesSqlDetailsArgs $;

        public Builder() {
            $ = new MetricExtensionQueryPropertiesSqlDetailsArgs();
        }

        public Builder(MetricExtensionQueryPropertiesSqlDetailsArgs defaults) {
            $ = new MetricExtensionQueryPropertiesSqlDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param content (Updatable) Sql statement or script file content as base64 encoded string
         * 
         * @return builder
         * 
         */
        public Builder content(Output<String> content) {
            $.content = content;
            return this;
        }

        /**
         * @param content (Updatable) Sql statement or script file content as base64 encoded string
         * 
         * @return builder
         * 
         */
        public Builder content(String content) {
            return content(Output.of(content));
        }

        /**
         * @param scriptFileName (Updatable) If a script needs to be executed, then provide file name of the script
         * 
         * @return builder
         * 
         */
        public Builder scriptFileName(@Nullable Output<String> scriptFileName) {
            $.scriptFileName = scriptFileName;
            return this;
        }

        /**
         * @param scriptFileName (Updatable) If a script needs to be executed, then provide file name of the script
         * 
         * @return builder
         * 
         */
        public Builder scriptFileName(String scriptFileName) {
            return scriptFileName(Output.of(scriptFileName));
        }

        public MetricExtensionQueryPropertiesSqlDetailsArgs build() {
            $.content = Objects.requireNonNull($.content, "expected parameter 'content' to be non-null");
            return $;
        }
    }

}