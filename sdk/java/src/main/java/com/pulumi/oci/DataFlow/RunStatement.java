// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DataFlow.RunStatementArgs;
import com.pulumi.oci.DataFlow.inputs.RunStatementState;
import com.pulumi.oci.DataFlow.outputs.RunStatementOutput;
import com.pulumi.oci.Utilities;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

/**
 * This resource provides the Run Statement resource in Oracle Cloud Infrastructure Data Flow service.
 * 
 * Executes a statement for a Session run.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.DataFlow.RunStatement;
 * import com.pulumi.oci.DataFlow.RunStatementArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testRunStatement = new RunStatement("testRunStatement", RunStatementArgs.builder()
 *             .code(runStatementCode)
 *             .runId(testRun.id())
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * RunStatements can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:DataFlow/runStatement:RunStatement test_run_statement &#34;runs/{runId}/statements/{statementId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DataFlow/runStatement:RunStatement")
public class RunStatement extends com.pulumi.resources.CustomResource {
    /**
     * The statement code to execute. Example: `println(sc.version)`
     * 
     */
    @Export(name="code", refs={String.class}, tree="[0]")
    private Output<String> code;

    /**
     * @return The statement code to execute. Example: `println(sc.version)`
     * 
     */
    public Output<String> code() {
        return this.code;
    }
    /**
     * The execution output of a statement.
     * 
     */
    @Export(name="outputs", refs={List.class,RunStatementOutput.class}, tree="[0,1]")
    private Output<List<RunStatementOutput>> outputs;

    /**
     * @return The execution output of a statement.
     * 
     */
    public Output<List<RunStatementOutput>> outputs() {
        return this.outputs;
    }
    /**
     * The execution progress.
     * 
     */
    @Export(name="progress", refs={Double.class}, tree="[0]")
    private Output<Double> progress;

    /**
     * @return The execution progress.
     * 
     */
    public Output<Double> progress() {
        return this.progress;
    }
    /**
     * The unique ID for the run
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="runId", refs={String.class}, tree="[0]")
    private Output<String> runId;

    /**
     * @return The unique ID for the run
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> runId() {
        return this.runId;
    }
    /**
     * The current state of this statement.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of this statement.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time a statement execution was completed, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2022-05-31T21:10:29.600Z`
     * 
     */
    @Export(name="timeCompleted", refs={String.class}, tree="[0]")
    private Output<String> timeCompleted;

    /**
     * @return The date and time a statement execution was completed, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2022-05-31T21:10:29.600Z`
     * 
     */
    public Output<String> timeCompleted() {
        return this.timeCompleted;
    }
    /**
     * The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public RunStatement(java.lang.String name) {
        this(name, RunStatementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public RunStatement(java.lang.String name, RunStatementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public RunStatement(java.lang.String name, RunStatementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataFlow/runStatement:RunStatement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private RunStatement(java.lang.String name, Output<java.lang.String> id, @Nullable RunStatementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataFlow/runStatement:RunStatement", name, state, makeResourceOptions(options, id), false);
    }

    private static RunStatementArgs makeArgs(RunStatementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? RunStatementArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static RunStatement get(java.lang.String name, Output<java.lang.String> id, @Nullable RunStatementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new RunStatement(name, id, state, options);
    }
}
