// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage;

import com.pulumi.core.Output;
import com.pulumi.core.TypeShape;
import com.pulumi.deployment.Deployment;
import com.pulumi.deployment.InvokeOptions;
import com.pulumi.deployment.InvokeOutputOptions;
import com.pulumi.oci.AiLanguage.inputs.GetEndpointArgs;
import com.pulumi.oci.AiLanguage.inputs.GetEndpointPlainArgs;
import com.pulumi.oci.AiLanguage.inputs.GetEndpointsArgs;
import com.pulumi.oci.AiLanguage.inputs.GetEndpointsPlainArgs;
import com.pulumi.oci.AiLanguage.inputs.GetModelArgs;
import com.pulumi.oci.AiLanguage.inputs.GetModelEvaluationResultsArgs;
import com.pulumi.oci.AiLanguage.inputs.GetModelEvaluationResultsPlainArgs;
import com.pulumi.oci.AiLanguage.inputs.GetModelPlainArgs;
import com.pulumi.oci.AiLanguage.inputs.GetModelTypeArgs;
import com.pulumi.oci.AiLanguage.inputs.GetModelTypePlainArgs;
import com.pulumi.oci.AiLanguage.inputs.GetModelsArgs;
import com.pulumi.oci.AiLanguage.inputs.GetModelsPlainArgs;
import com.pulumi.oci.AiLanguage.inputs.GetProjectArgs;
import com.pulumi.oci.AiLanguage.inputs.GetProjectPlainArgs;
import com.pulumi.oci.AiLanguage.inputs.GetProjectsArgs;
import com.pulumi.oci.AiLanguage.inputs.GetProjectsPlainArgs;
import com.pulumi.oci.AiLanguage.outputs.GetEndpointResult;
import com.pulumi.oci.AiLanguage.outputs.GetEndpointsResult;
import com.pulumi.oci.AiLanguage.outputs.GetModelEvaluationResultsResult;
import com.pulumi.oci.AiLanguage.outputs.GetModelResult;
import com.pulumi.oci.AiLanguage.outputs.GetModelTypeResult;
import com.pulumi.oci.AiLanguage.outputs.GetModelsResult;
import com.pulumi.oci.AiLanguage.outputs.GetProjectResult;
import com.pulumi.oci.AiLanguage.outputs.GetProjectsResult;
import com.pulumi.oci.Utilities;
import java.util.concurrent.CompletableFuture;

public final class AiLanguageFunctions {
    /**
     * This data source provides details about a specific Endpoint resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets an endpoint by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetEndpointResult> getEndpoint(GetEndpointArgs args) {
        return getEndpoint(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Endpoint resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets an endpoint by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetEndpointResult> getEndpointPlain(GetEndpointPlainArgs args) {
        return getEndpointPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Endpoint resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets an endpoint by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetEndpointResult> getEndpoint(GetEndpointArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getEndpoint:getEndpoint", TypeShape.of(GetEndpointResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Endpoint resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets an endpoint by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetEndpointResult> getEndpoint(GetEndpointArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getEndpoint:getEndpoint", TypeShape.of(GetEndpointResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Endpoint resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets an endpoint by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetEndpointResult> getEndpointPlain(GetEndpointPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:AiLanguage/getEndpoint:getEndpoint", TypeShape.of(GetEndpointResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Endpoints in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of Endpoints.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetEndpointsResult> getEndpoints(GetEndpointsArgs args) {
        return getEndpoints(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Endpoints in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of Endpoints.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetEndpointsResult> getEndpointsPlain(GetEndpointsPlainArgs args) {
        return getEndpointsPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Endpoints in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of Endpoints.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetEndpointsResult> getEndpoints(GetEndpointsArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getEndpoints:getEndpoints", TypeShape.of(GetEndpointsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Endpoints in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of Endpoints.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetEndpointsResult> getEndpoints(GetEndpointsArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getEndpoints:getEndpoints", TypeShape.of(GetEndpointsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Endpoints in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of Endpoints.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetEndpointsResult> getEndpointsPlain(GetEndpointsPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:AiLanguage/getEndpoints:getEndpoints", TypeShape.of(GetEndpointsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Model resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets a model by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelResult> getModel(GetModelArgs args) {
        return getModel(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Model resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets a model by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetModelResult> getModelPlain(GetModelPlainArgs args) {
        return getModelPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Model resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets a model by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelResult> getModel(GetModelArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getModel:getModel", TypeShape.of(GetModelResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Model resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets a model by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelResult> getModel(GetModelArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getModel:getModel", TypeShape.of(GetModelResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Model resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets a model by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetModelResult> getModelPlain(GetModelPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:AiLanguage/getModel:getModel", TypeShape.of(GetModelResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Model Evaluation Results in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Get a (paginated) list of evaluation results for a given model.
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
     * import com.pulumi.oci.AiLanguage.AiLanguageFunctions;
     * import com.pulumi.oci.AiLanguage.inputs.GetModelEvaluationResultsArgs;
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
     *         final var testModelEvaluationResults = AiLanguageFunctions.getModelEvaluationResults(GetModelEvaluationResultsArgs.builder()
     *             .modelId(testModel.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelEvaluationResultsResult> getModelEvaluationResults(GetModelEvaluationResultsArgs args) {
        return getModelEvaluationResults(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Model Evaluation Results in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Get a (paginated) list of evaluation results for a given model.
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
     * import com.pulumi.oci.AiLanguage.AiLanguageFunctions;
     * import com.pulumi.oci.AiLanguage.inputs.GetModelEvaluationResultsArgs;
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
     *         final var testModelEvaluationResults = AiLanguageFunctions.getModelEvaluationResults(GetModelEvaluationResultsArgs.builder()
     *             .modelId(testModel.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetModelEvaluationResultsResult> getModelEvaluationResultsPlain(GetModelEvaluationResultsPlainArgs args) {
        return getModelEvaluationResultsPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Model Evaluation Results in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Get a (paginated) list of evaluation results for a given model.
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
     * import com.pulumi.oci.AiLanguage.AiLanguageFunctions;
     * import com.pulumi.oci.AiLanguage.inputs.GetModelEvaluationResultsArgs;
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
     *         final var testModelEvaluationResults = AiLanguageFunctions.getModelEvaluationResults(GetModelEvaluationResultsArgs.builder()
     *             .modelId(testModel.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelEvaluationResultsResult> getModelEvaluationResults(GetModelEvaluationResultsArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getModelEvaluationResults:getModelEvaluationResults", TypeShape.of(GetModelEvaluationResultsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Model Evaluation Results in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Get a (paginated) list of evaluation results for a given model.
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
     * import com.pulumi.oci.AiLanguage.AiLanguageFunctions;
     * import com.pulumi.oci.AiLanguage.inputs.GetModelEvaluationResultsArgs;
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
     *         final var testModelEvaluationResults = AiLanguageFunctions.getModelEvaluationResults(GetModelEvaluationResultsArgs.builder()
     *             .modelId(testModel.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelEvaluationResultsResult> getModelEvaluationResults(GetModelEvaluationResultsArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getModelEvaluationResults:getModelEvaluationResults", TypeShape.of(GetModelEvaluationResultsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Model Evaluation Results in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Get a (paginated) list of evaluation results for a given model.
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
     * import com.pulumi.oci.AiLanguage.AiLanguageFunctions;
     * import com.pulumi.oci.AiLanguage.inputs.GetModelEvaluationResultsArgs;
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
     *         final var testModelEvaluationResults = AiLanguageFunctions.getModelEvaluationResults(GetModelEvaluationResultsArgs.builder()
     *             .modelId(testModel.id())
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetModelEvaluationResultsResult> getModelEvaluationResultsPlain(GetModelEvaluationResultsPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:AiLanguage/getModelEvaluationResults:getModelEvaluationResults", TypeShape.of(GetModelEvaluationResultsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Model Type resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets model capabilities
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
     * import com.pulumi.oci.AiLanguage.AiLanguageFunctions;
     * import com.pulumi.oci.AiLanguage.inputs.GetModelTypeArgs;
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
     *         final var testModelType = AiLanguageFunctions.getModelType(GetModelTypeArgs.builder()
     *             .modelType(modelTypeModelType)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelTypeResult> getModelType(GetModelTypeArgs args) {
        return getModelType(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Model Type resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets model capabilities
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
     * import com.pulumi.oci.AiLanguage.AiLanguageFunctions;
     * import com.pulumi.oci.AiLanguage.inputs.GetModelTypeArgs;
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
     *         final var testModelType = AiLanguageFunctions.getModelType(GetModelTypeArgs.builder()
     *             .modelType(modelTypeModelType)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetModelTypeResult> getModelTypePlain(GetModelTypePlainArgs args) {
        return getModelTypePlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Model Type resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets model capabilities
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
     * import com.pulumi.oci.AiLanguage.AiLanguageFunctions;
     * import com.pulumi.oci.AiLanguage.inputs.GetModelTypeArgs;
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
     *         final var testModelType = AiLanguageFunctions.getModelType(GetModelTypeArgs.builder()
     *             .modelType(modelTypeModelType)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelTypeResult> getModelType(GetModelTypeArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getModelType:getModelType", TypeShape.of(GetModelTypeResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Model Type resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets model capabilities
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
     * import com.pulumi.oci.AiLanguage.AiLanguageFunctions;
     * import com.pulumi.oci.AiLanguage.inputs.GetModelTypeArgs;
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
     *         final var testModelType = AiLanguageFunctions.getModelType(GetModelTypeArgs.builder()
     *             .modelType(modelTypeModelType)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelTypeResult> getModelType(GetModelTypeArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getModelType:getModelType", TypeShape.of(GetModelTypeResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Model Type resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets model capabilities
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
     * import com.pulumi.oci.AiLanguage.AiLanguageFunctions;
     * import com.pulumi.oci.AiLanguage.inputs.GetModelTypeArgs;
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
     *         final var testModelType = AiLanguageFunctions.getModelType(GetModelTypeArgs.builder()
     *             .modelType(modelTypeModelType)
     *             .build());
     * 
     *     }
     * }
     * }
     * </pre>
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetModelTypeResult> getModelTypePlain(GetModelTypePlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:AiLanguage/getModelType:getModelType", TypeShape.of(GetModelTypeResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Models in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of models.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelsResult> getModels(GetModelsArgs args) {
        return getModels(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Models in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of models.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetModelsResult> getModelsPlain(GetModelsPlainArgs args) {
        return getModelsPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Models in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of models.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelsResult> getModels(GetModelsArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getModels:getModels", TypeShape.of(GetModelsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Models in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of models.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetModelsResult> getModels(GetModelsArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getModels:getModels", TypeShape.of(GetModelsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Models in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of models.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetModelsResult> getModelsPlain(GetModelsPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:AiLanguage/getModels:getModels", TypeShape.of(GetModelsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Project resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets a Project by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetProjectResult> getProject(GetProjectArgs args) {
        return getProject(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Project resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets a Project by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetProjectResult> getProjectPlain(GetProjectPlainArgs args) {
        return getProjectPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Project resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets a Project by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetProjectResult> getProject(GetProjectArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getProject:getProject", TypeShape.of(GetProjectResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Project resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets a Project by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetProjectResult> getProject(GetProjectArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getProject:getProject", TypeShape.of(GetProjectResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Project resource in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Gets a Project by identifier
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetProjectResult> getProjectPlain(GetProjectPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:AiLanguage/getProject:getProject", TypeShape.of(GetProjectResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Projects in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of  Projects.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetProjectsResult> getProjects(GetProjectsArgs args) {
        return getProjects(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Projects in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of  Projects.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetProjectsResult> getProjectsPlain(GetProjectsPlainArgs args) {
        return getProjectsPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Projects in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of  Projects.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetProjectsResult> getProjects(GetProjectsArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getProjects:getProjects", TypeShape.of(GetProjectsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Projects in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of  Projects.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static Output<GetProjectsResult> getProjects(GetProjectsArgs args, InvokeOutputOptions options) {
        return Deployment.getInstance().invoke("oci:AiLanguage/getProjects:getProjects", TypeShape.of(GetProjectsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Projects in Oracle Cloud Infrastructure Ai Language service.
     * 
     * Returns a list of  Projects.
     * 
     * ## Example Usage
     * 
     * &lt;!--Start PulumiCodeChooser --&gt;
     * &lt;!--End PulumiCodeChooser --&gt;
     * 
     */
    public static CompletableFuture<GetProjectsResult> getProjectsPlain(GetProjectsPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:AiLanguage/getProjects:getProjects", TypeShape.of(GetProjectsResult.class), args, Utilities.withVersion(options));
    }
}
