// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Artifacts.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class ContainerRepositoryReadmeArgs extends com.pulumi.resources.ResourceArgs {

    public static final ContainerRepositoryReadmeArgs Empty = new ContainerRepositoryReadmeArgs();

    /**
     * (Updatable) Readme content. Avoid entering confidential information.
     * 
     */
    @Import(name="content", required=true)
    private Output<String> content;

    /**
     * @return (Updatable) Readme content. Avoid entering confidential information.
     * 
     */
    public Output<String> content() {
        return this.content;
    }

    /**
     * (Updatable) Readme format. Supported formats are text/plain and text/markdown.
     * 
     */
    @Import(name="format", required=true)
    private Output<String> format;

    /**
     * @return (Updatable) Readme format. Supported formats are text/plain and text/markdown.
     * 
     */
    public Output<String> format() {
        return this.format;
    }

    private ContainerRepositoryReadmeArgs() {}

    private ContainerRepositoryReadmeArgs(ContainerRepositoryReadmeArgs $) {
        this.content = $.content;
        this.format = $.format;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ContainerRepositoryReadmeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ContainerRepositoryReadmeArgs $;

        public Builder() {
            $ = new ContainerRepositoryReadmeArgs();
        }

        public Builder(ContainerRepositoryReadmeArgs defaults) {
            $ = new ContainerRepositoryReadmeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param content (Updatable) Readme content. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder content(Output<String> content) {
            $.content = content;
            return this;
        }

        /**
         * @param content (Updatable) Readme content. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder content(String content) {
            return content(Output.of(content));
        }

        /**
         * @param format (Updatable) Readme format. Supported formats are text/plain and text/markdown.
         * 
         * @return builder
         * 
         */
        public Builder format(Output<String> format) {
            $.format = format;
            return this;
        }

        /**
         * @param format (Updatable) Readme format. Supported formats are text/plain and text/markdown.
         * 
         * @return builder
         * 
         */
        public Builder format(String format) {
            return format(Output.of(format));
        }

        public ContainerRepositoryReadmeArgs build() {
            $.content = Objects.requireNonNull($.content, "expected parameter 'content' to be non-null");
            $.format = Objects.requireNonNull($.format, "expected parameter 'format' to be non-null");
            return $;
        }
    }

}