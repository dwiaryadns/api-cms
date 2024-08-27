<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Auth\AuthenticationException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Throwable;

class Handler extends ExceptionHandler
{
    /**
     * The list of the inputs that are never flashed to the session on validation exceptions.
     *
     * @var array<int, string>
     */
    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    /**
     * Register the exception handling callbacks for the application.
     */
    public function register(): void
    {
        $this->reportable(function (Throwable $e) {
            //
        });
        $this->renderable(function (Throwable $e, $request) {

            if ($e instanceof HttpExceptionInterface) {
                $statusCode = $e->getStatusCode();

                switch ($statusCode) {
                    case 400:
                        return new JsonResponse([
                            'success' => false,
                            'message' => 'Bad Request.',
                        ], Response::HTTP_BAD_REQUEST);

                    case 401:
                        return new JsonResponse([
                            'success' => false,
                            'message' => 'Unauthenticated.',
                        ], Response::HTTP_UNAUTHORIZED);

                    case 403:
                        return new JsonResponse([
                            'success' => false,
                            'message' => 'Forbidden.',
                        ], Response::HTTP_FORBIDDEN);

                    case 404:
                        return new JsonResponse([
                            'success' => false,
                            'message' => 'Not Found.',
                        ], Response::HTTP_NOT_FOUND);

                    case 405:
                        return new JsonResponse([
                            'success' => false,
                            'message' => 'Method Not Allowed.',
                        ], Response::HTTP_METHOD_NOT_ALLOWED);

                    case 422:
                        return new JsonResponse([
                            'success' => false,
                            'message' => 'Unprocessable Entity.',
                        ], Response::HTTP_UNPROCESSABLE_ENTITY);

                    case 429:
                        return new JsonResponse([
                            'success' => false,
                            'message' => 'Too Many Requests.',
                        ], Response::HTTP_TOO_MANY_REQUESTS);

                    case 500:
                        return new JsonResponse([
                            'success' => false,
                            'message' => 'Internal Server Error.',
                        ], Response::HTTP_INTERNAL_SERVER_ERROR);

                    case 503:
                        return new JsonResponse([
                            'success' => false,
                            'message' => 'Service Unavailable.',
                        ], Response::HTTP_SERVICE_UNAVAILABLE);

                    default:
                        return new JsonResponse([
                            'success' => false,
                            'message' => 'An unexpected error occurred.',
                        ], $statusCode);
                }
            }
        });
    }
    protected function unauthenticated($request, AuthenticationException $exception)
    {
        return response()->json(
            [
                'success' => false,
                'message' => 'Unauthenticated.',
            ],
            401
        );
    }
}
