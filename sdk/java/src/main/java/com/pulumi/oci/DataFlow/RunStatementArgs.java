// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class RunStatementArgs extends com.pulumi.resources.ResourceArgs {

    public static final RunStatementArgs Empty = new RunStatementArgs();

    /**
     * The statement code to execute. Example: `println(sc.version)`
     * 
     */
    @Import(name="code", required=true)
    private Output<String> code;

    /**
     * @return The statement code to execute. Example: `println(sc.version)`
     * 
     */
    public Output<String> code() {
        return this.code;
    }

    /**
     * The unique ID for the run
     * 
     */
    @Import(name="runId", required=true)
    private Output<String> runId;

    /**
     * @return The unique ID for the run
     * 
     */
    public Output<String> runId() {
        return this.runId;
    }

    private RunStatementArgs() {}

    private RunStatementArgs(RunStatementArgs $) {
        this.code = $.code;
        this.runId = $.runId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RunStatementArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RunStatementArgs $;

        public Builder() {
            $ = new RunStatementArgs();
        }

        public Builder(RunStatementArgs defaults) {
            $ = new RunStatementArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param code The statement code to execute. Example: `println(sc.version)`
         * 
         * @return builder
         * 
         */
        public Builder code(Output<String> code) {
            $.code = code;
            return this;
        }

        /**
         * @param code The statement code to execute. Example: `println(sc.version)`
         * 
         * @return builder
         * 
         */
        public Builder code(String code) {
            return code(Output.of(code));
        }

        /**
         * @param runId The unique ID for the run
         * 
         * @return builder
         * 
         */
        public Builder runId(Output<String> runId) {
            $.runId = runId;
            return this;
        }

        /**
         * @param runId The unique ID for the run
         * 
         * @return builder
         * 
         */
        public Builder runId(String runId) {
            return runId(Output.of(runId));
        }

        public RunStatementArgs build() {
            $.code = Objects.requireNonNull($.code, "expected parameter 'code' to be non-null");
            $.runId = Objects.requireNonNull($.runId, "expected parameter 'runId' to be non-null");
            return $;
        }
    }

}